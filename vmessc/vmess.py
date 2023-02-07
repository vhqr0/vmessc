import time
import random
import struct
import asyncio

from hashlib import md5
from hmac import HMAC

from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import CFB
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from typing import Optional
from typing_extensions import Self
from asyncio import StreamReader, StreamWriter

from .node import VmessNode
from .proxy import ProxyAcceptor


def fnv32a(buf: bytes) -> bytes:
    hval = 0x811c9dc5
    fnv_32_prime = 0x01000193
    for ch in buf:
        hval = ((hval ^ ch) * fnv_32_prime) & 0xffffffff
    return hval.to_bytes(4, 'big')


class VmessConnector:
    reader: StreamReader  # client reader
    writer: StreamWriter  # client writer
    peer_reader: Optional[StreamReader]  # peer reader
    peer_writer: Optional[StreamWriter]  # peer writer
    addr: str  # request addr
    port: int  # request port
    rest: bytes  # payload shipped with request
    peer: VmessNode  # peer vmess node
    key: bytes  # vmess crypt key
    iv: bytes  # vmess crypt iv
    rv: int  # vmess auth rv

    tasks = set()

    def __init__(self, reader: StreamReader, writer: StreamWriter, addr: str,
                 port: int, rest: bytes, peer: VmessNode):
        self.reader = reader
        self.writer = writer
        self.peer_reader = None
        self.peer_writer = None
        self.addr = addr
        self.port = port
        self.rest = rest
        self.peer = peer
        self.key = random.randbytes(16)
        self.iv = random.randbytes(16)
        self.rv = random.getrandbits(8)

    @classmethod
    def from_acceptor(cls, acceptor: ProxyAcceptor, peer: VmessNode) -> Self:
        return cls(reader=acceptor.reader,
                   writer=acceptor.writer,
                   addr=acceptor.addr,
                   port=acceptor.port,
                   rest=acceptor.rest,
                   peer=peer)

    async def connect(self):
        self.peer_reader, self.peer_writer = await asyncio.open_connection(
            self.peer.addr, self.peer.port)
        task1 = asyncio.create_task(self.io_copy_from_client())
        task2 = asyncio.create_task(self.io_copy_from_peer())
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

    def pack_req(self) -> bytes:
        ts = int(time.time())
        ts_bytes = ts.to_bytes(8, 'big')

        addr_bytes = self.addr.encode()
        alen = len(addr_bytes)

        plen = random.getrandbits(4)

        # ver(B)          : 1
        # iv(16s)         : iv
        # key(16s)        : key
        # rv(B)           : rv
        # opts(B)         : 1
        # plen|secmeth(B) : plen|3
        # res(B)          : 0
        # cmd(B)          : 1
        # port(H)         : port
        # atype(B)        : 2
        # alen(B)         : alen
        # addr({alen}s)   : addr
        # random({plen}s) : randbytes
        req = struct.pack(
            f'!B16s16sBBBBBHBB{alen}s{plen}s',
            1,
            self.iv,
            self.key,
            self.rv,
            1,
            (plen << 4) + 3,
            0,
            1,
            self.port,
            2,
            alen,
            addr_bytes,
            random.randbytes(plen),
        )
        req += fnv32a(req)

        cipher = Cipher(
            AES(
                md5(self.peer.uuid.bytes +
                    b'c48619fe-8f02-49e0-b9e9-edf763e17e21').digest()),
            CFB(md5(4 * ts_bytes).digest()),
        )
        encryptor = cipher.encryptor()
        req = encryptor.update(req) + encryptor.finalize()

        auth = HMAC(key=self.peer.uuid.bytes, msg=ts_bytes,
                    digestmod='md5').digest()

        return auth + req

    async def io_copy_from_client(self):
        aesgcm, iv, count = AESGCM(self.key), self.iv[2:12], 0
        self.peer_writer.write(self.pack_req())
        if self.rest:
            buf = aesgcm.encrypt(struct.pack('!H', count) + iv, self.rest, b'')
            buf = struct.pack('!H', len(buf)) + buf
            self.peer_writer.write(buf)
            count += 1
        await self.peer_writer.drain()
        while True:
            buf = await self.reader.read(4096)
            if len(buf) == 0:
                buf = aesgcm.encrypt(struct.pack('!H', count) + iv, b'', b'')
                self.peer_writer.write(buf)
                if self.peer_writer.can_write_eof():
                    self.peer_writer.write_eof()
                break
            else:
                buf = aesgcm.encrypt(struct.pack('!H', count) + iv, buf, b'')
                buf = struct.pack('!H', len(buf)) + buf
                self.peer_writer.write(buf)
                await self.peer_writer.drain()
                count += 1

    async def io_copy_from_peer(self):
        key, iv = md5(self.key).digest(), md5(self.iv).digest()
        buf = await self.peer_reader.readexactly(4)
        cipher = Cipher(AES(key), CFB(iv))
        encryptor = cipher.encryptor()
        buf = encryptor.update(buf) + encryptor.finalize()
        rrv, opts, cmd, clen = struct.unpack('!BBBB', buf)
        if rrv != self.rv or opts != 0 or cmd != 0 or clen != 0:
            raise struct.error('invalid vmess response')

        aesgcm, iv, count = AESGCM(key), iv[2:12], 0
        eof = False
        while True:
            try:
                buf = await self.peer_reader.readexactly(2)
                blen, = struct.unpack('!H', buf)
                buf = await self.peer_reader.readexactly(blen)
            except asyncio.IncompleteReadError:
                eof = True
            if eof:
                if self.writer.can_write_eof():
                    self.writer.write_eof()
                break
            else:
                buf = aesgcm.decrypt(struct.pack('!H', count) + iv, buf, b'')
                self.writer.write(buf)
                await self.writer.drain()
                count += 1