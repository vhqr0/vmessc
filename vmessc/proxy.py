import re
import struct
import socket
import asyncio

from typing import Optional
from typing_extensions import Self
from asyncio import StreamReader, StreamWriter


class ProxyAcceptor:
    reader: StreamReader  # client reader
    writer: StreamWriter  # client writer
    buf: bytes  # request buffer
    addr: str  # request addr
    port: int  # request port
    rest: bytes  # payload shipped with request

    http_request_re = re.compile(r'^(\w+) [^ ]+ (HTTP/[^ \r\n]+)\r\n')
    http_host_re = re.compile(
        r'\r\nHost: ([^ :\[\]\r\n]+|\[[:0-9a-fA-F]+\])(:([0-9]+))?\r\n')

    def __init__(self, reader: StreamReader, writer: StreamWriter):
        '''
        Args:
        - reader: asyncio.StreamReader
        - writer: asyncio.StreamWriter
        # These args accept from asyncio.start_server as callback.
        '''
        self.reader = reader
        self.writer = writer
        self.buf = b''
        self.addr = ''
        self.port = 0
        self.rest = b''

    async def accept(self):
        '''Accept a proxy request, auto detect socks5/http.
        Return:
        - self.addr: str
        - self.port: int
        # Request host (addr:port).
        - self.rest: bytes
        # Payload shipped with request, send it on conneciton.
        '''
        self.buf = await self.reader.read(4096)
        if self.buf[0] == 5:
            await self.accept_socks5()
        else:
            await self.accept_http()

    async def accept_socks5(self):
        '''Accept socks5 proxy request.
        Args:
        - self.buf
        # Store request to it before call this method.

        Return:
        - self.addr: str
        - self.port: int
        - self.rest: bytes (always b"")
        # See self.accept.
        '''
        nmeths = self.buf[1]
        ver, nmeths, meths = struct.unpack(f'!BB{nmeths}s', self.buf)
        if ver != 5 or 0 not in meths:
            raise struct.error('invalid socks5 request')
        self.writer.write(b'\x05\x00')
        await self.writer.drain()
        self.buf = await self.reader.read(4096)  # Notice: read
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
        '''Accept http proxy request.
        Same as self.accept_socks5 but self.rest is not always b"".
        '''
        pos = self.buf.find(b'\r\n\r\n')
        if pos < 0:
            raise struct.error('invalid http request')
        headers = self.buf[:pos + 2].decode()
        body = self.buf[pos + 4:]
        request = self.http_request_re.search(headers)
        host = self.http_host_re.search(headers)
        if request is None or host is None:
            raise struct.error('invalid http request')
        method = request[1]
        version = request[2]
        addr = host[1]
        port = host[3]
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
    '''Python version of Golang::io.Copy.
    Copy from reader to writer.

    Args:
    - reader: asyncio.Streamreader
    - writer: asyncio.StreamWriter
    # Theses args accept from asyncio.start_server as callback,
    # or asyncio.open_connection as return.
    '''
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
    reader: StreamReader  # client reader
    writer: StreamWriter  # client writer
    peer_reader: Optional[StreamReader]  # peer reader
    peer_writer: Optional[StreamWriter]  # peer writer
    addr: str  # request addr
    port: int  # request port
    rest: bytes  # payload shipped with request

    tasks = set()

    def __init__(self, reader: StreamReader, writer: StreamWriter, addr: str,
                 port: int, rest: bytes):
        self.reader = reader
        self.writer = writer
        self.peer_reader = None
        self.peer_writer = None
        self.addr = addr
        self.port = port
        self.rest = rest

    @classmethod
    def from_acceptor(cls, acceptor: ProxyAcceptor) -> Self:
        return cls(reader=acceptor.reader,
                   writer=acceptor.writer,
                   addr=acceptor.addr,
                   port=acceptor.port,
                   rest=acceptor.rest)

    async def connect(self):
        '''
        Args:
        - self.addr: str
        - self.port: int
        - self.rest: bytes

        Open connection and then proxy to addr:port.
        '''
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
