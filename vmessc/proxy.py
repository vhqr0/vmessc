"""HTTP/Socks5 proxy protocol implementation.

Provide an acceptor to accept a http/socks5 (auto detect) proxy
request, and a connector to make raw connection.

Usage example:

  async def proxy_handler(reader, writer):
    # create acceptor and accept proxy request
    acceptor = ProxyAcceptor(reader, writer)
    await acceptor.accept()
    # create connector and make connection
    connector = RawConnector.from_acceptor(acceptor)
    await connector.connect()

  # create server and serve
  server = await asyncio.start_server(proxy_handler, '0.0.0.0', '1080')
  async with server:
    await server.serve_forever()
"""

import re
import struct
import socket
import asyncio

from typing import Optional
from typing_extensions import Self
from asyncio import StreamReader, StreamWriter


class ProxyAcceptor:
    """Accept a proxy request, auto detect http/socks5.

    Accept a proxy request by awaiting acceptor.accept(), and request
    information will be stored in acceptor.addr, acceptor.port and
    acceptor.rest.

    Attributes:
        reader: Client reader.
        writer: Clinet writer.
        buf: Buffer to store request.
        addr: Addr of requested host.
        port: Port of requested host.
        rest: Payload shipped with request.
    """
    reader: StreamReader
    writer: StreamWriter
    buf: bytes
    addr: str
    port: int
    rest: bytes

    http_request_re = re.compile(r'^(\w+) [^ ]+ (HTTP/[^ \r\n]+)\r\n')
    http_host_re = re.compile(
        r'\r\nHost: ([^ :\[\]\r\n]+|\[[:0-9a-fA-F]+\])(:([0-9]+))?\r\n')

    def __init__(self, reader: StreamReader, writer: StreamWriter):
        """
        Args:
            reader: Accept from start_server as callback args.
            writer: Accept from start_server as callback args.
        """
        self.reader = reader
        self.writer = writer
        self.buf = b''
        self.addr = ''
        self.port = 0
        self.rest = b''

    async def accept(self):
        """Accept a proxy request, auto detect http/socks5.

        Returns:
            self.addr: Addr of requested host.
            self.port: Port of requested host.
            self.rest: Payload shipped with request, should be sent on
              connecting.
        """
        self.buf = await self.reader.read(4096)
        if self.buf[0] == 5:
            await self.accept_socks5()
        else:
            await self.accept_http()

    async def accept_socks5(self):
        """Accept socks5 proxy request.

        Args:
            self.buf: Store socks5 proxy request (auth handshake).

        Return:
            self.addr: Addr of requested host.
            self.port: Port of requested host.
            self.rest: Payload shipped with request, for socks5 is always b''.
        """
        nmeths = self.buf[1]
        ver, nmeths, meths = struct.unpack(f'!BB{nmeths}s', self.buf)
        if ver != 5 or 0 not in meths:
            raise struct.error('invalid socks5 request')
        self.writer.write(b'\x05\x00')
        await self.writer.drain()

        self.buf = await self.reader.read(4096)  # read to buf again
        atype = self.buf[3]
        if atype == 3:  # domain
            alen = self.buf[4]
            ver, cmd, rsv, atype, alen, addr, port = struct.unpack(
                f'!BBBBB{alen}sH', self.buf)
            self.addr = addr.decode()
            self.port = port
        elif atype == 1:  # ipv4
            ver, cmd, rsv, atype, addr, port = struct.unpack(
                '!BBBB4sH', self.buf)
            self.addr = socket.inet_ntop(socket.AF_INET, addr)
            self.port = port
        elif atype == 4:  # ipv6
            ver, cmd, rsv, atype, addr, port = struct.unpack(
                '!BBBB16sH', self.buf)
            self.addr = socket.inet_ntop(socket.AF_INET6, addr)
            self.port = port
        else:
            raise struct.error('invalid socks5 header')

        if ver != 5 or cmd != 1 or rsv != 0:
            raise struct.error('invalid socks5 header')
        self.writer.write(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')
        await self.writer.drain()

    async def accept_http(self):
        """Accept http proxy request.

        Args:
            self.buf: Store http proxy request.

        Return:
            self.addr: Addr of requested host.
            self.port: Port of requested host.
            self.rest: Payload shipped with request.
        """
        pos = self.buf.find(b'\r\n\r\n')
        if pos < 0:
            raise struct.error('invalid http request')
        headers = self.buf[:pos + 2].decode()
        body = self.buf[pos + 4:]

        request = self.http_request_re.search(headers)
        host = self.http_host_re.search(headers)
        if request is None or host is None:
            raise struct.error('invalid http request')
        method, version = request[1], request[2]
        addr, port = host[1], host[3]

        self.addr = addr if addr[0] != '[' else addr[1:-1]
        self.port = int(port) if port else 80

        if method == 'CONNECT':
            self.writer.write(f'{version} 200 Connection Established\r\n'
                              'Connection close\r\n\r\n'.encode())
            await self.writer.drain()
            self.rest = body
        else:
            headers = '\r\n'.join(header for header in headers.split('\r\n')
                                  if not header.startswith('Proxy-'))
            self.rest = headers.encode() + b'\r\n' + body


async def io_copy(reader: StreamReader, writer: StreamWriter):
    """Python version of Golang::io.Copy, copy from reader to writer.

    Args:
        reader: Accept from start_server as callback args, or open_connection
          as return values.
        writer: Accept from start_server as callback args, or open_connection
          as return values.
    """
    while True:
        buf = await reader.read(4096)
        if len(buf) == 0:
            if writer.can_write_eof():
                writer.write_eof()
            break
        else:
            writer.write(buf)
            await writer.drain()


class RawConnector:
    """Make raw connection between client and requested host.

    Connect to requested host self.addr:self.port, send self.rest on
    connecting if possible, and then relay traffic between client and
    requested host, by awaiting connector.connect().

    Attributes:
        reader: Client reader.
        writer: Clinet writer.
        peer_reader: Peer reader.
        peer_writer: Peer writer.
        addr: Addr of requested host.
        port: Port of requested host.
        rest: Payload shipped with request.
    """
    reader: StreamReader
    writer: StreamWriter
    peer_reader: Optional[StreamReader]
    peer_writer: Optional[StreamWriter]
    addr: str
    port: int
    rest: bytes

    tasks = set()

    def __init__(self, reader: StreamReader, writer: StreamWriter, addr: str,
                 port: int, rest: bytes):
        """
        Args:
            reader: Accept from start_server as callback args.
            writer: Accept from start_server as callback args.
            addr: Addr of requested host accept by acceptor.
            port: Port of requested host accept by acceptor.
            rest: Payload shipped with request.
        """
        self.reader = reader
        self.writer = writer
        self.peer_reader = None
        self.peer_writer = None
        self.addr = addr
        self.port = port
        self.rest = rest

    @classmethod
    def from_acceptor(cls, acceptor: ProxyAcceptor) -> Self:
        """Create connector from acceptor.

        Args:
            acceptor: An acceptor have awaited acceptor.accept.

        Returns:
            Connector initialized from acceptor.
        """
        return cls(reader=acceptor.reader,
                   writer=acceptor.writer,
                   addr=acceptor.addr,
                   port=acceptor.port,
                   rest=acceptor.rest)

    async def connect(self):
        """Make connection."""
        self.peer_reader, self.peer_writer = await asyncio.open_connection(
            self.addr, self.port)
        if self.rest:
            self.peer_writer.write(self.rest)
            await self.peer_writer.drain()

        task1 = asyncio.create_task(io_copy(self.reader, self.peer_writer))
        task2 = asyncio.create_task(io_copy(self.peer_reader, self.writer))
        self.tasks.add(task1)
        self.tasks.add(task2)
        task1.add_done_callback(self.tasks.discard)
        task2.add_done_callback(self.tasks.discard)

        try:
            await asyncio.gather(task1, task2)
        except Exception:
            if not task1.cancelled():
                task1.cancel()
            if not task2.cancelled():
                task2.cancel()
            raise
