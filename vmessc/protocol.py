import time
import random
import re
import struct
import socket

import asyncio

from hashlib import md5
from hmac import HMAC

from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import CFB
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from enum import Enum
from uuid import UUID
from asyncio import StreamReader, StreamWriter

from typing import Tuple

from .types import Peer
from .util import fnv32a


# accept ######################################################################


class Socks5Atype(Enum):
    Domain = 3
    IPv4 = 1
    IPv6 = 4


async def socks5_accept(
    buf: bytes, reader: StreamReader, writer: StreamWriter
) -> Tuple[str, int, bytes]:
    nmeths = buf[1]
    ver, nmeths, meths = struct.unpack(f"!BB{nmeths}s", buf)
    if ver != 5 or 0 not in meths:
        raise struct.error("invalid socks5 request")
    writer.write(b"\x05\x00")
    await writer.drain()
    buf = await reader.read(4096)
    atype = Socks5Atype(buf[3])
    match atype:
        case Socks5Atype.Domain:
            alen = buf[4]
            ver, cmd, rsv, atype, alen, addr_bytes, port = struct.unpack(
                f"!BBBBB{alen}sH", buf
            )
            addr = addr_bytes.decode()
        case Socks5Atype.IPv4:
            ver, cmd, rsv, atype, addr_bytes, port = struct.unpack("!BBBB4sH", buf)
            addr = socket.inet_ntop(socket.AF_INET, addr_bytes)
        case Socks5Atype.IPv6:
            ver, cmd, rsv, atype, addr_bytes, port = struct.unpack("!BBBB16sH", buf)
            addr = socket.inet_ntop(socket.AF_INET6, addr_bytes)
    if ver != 5 or cmd != 1 or rsv != 0:
        raise struct.error("invalid socks5 request")
    writer.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
    await writer.drain()
    return addr, port, b""


http_re1 = re.compile(r"^(\w+) [^ ]+ (HTTP/[^ \r\n]+)\r\n")
http_re2 = re.compile(r"\r\nHost: ([^ :\[\]\r\n]+|\[[:0-9a-fA-F]+\])(:([0-9]+))?\r\n")


async def http_accept(
    buf: bytes, reader: StreamReader, writer: StreamWriter
) -> Tuple[str, int, bytes]:
    pos = buf.find(b"\r\n\r\n")
    if pos < 0:
        raise struct.error("invalid http request")
    headers = buf[: pos + 2].decode()
    rest = buf[pos + 4 :]
    re_res1 = http_re1.search(headers)
    re_res2 = http_re2.search(headers)
    if re_res1 is None or re_res2 is None:
        raise struct.error("invalid http request")
    method = re_res1[1]
    version = re_res1[2]
    addr = re_res2[1]
    port = re_res2[3]
    addr = addr if addr[0] != "[" else addr[1:-1]
    port = int(port) if port else 80
    if method == "CONNECT":
        writer.write(
            f"{version} 200 Connection Established\r\nConnection: close\r\n\r\n".encode()
        )
        await writer.drain()
    else:
        rest = (
            "\r\n".join(
                header
                for header in headers.split("\r\n")
                if not header.startswith("Proxy-")
            ).encode()
            + b"\r\n"
            + rest
        )
    return addr, port, rest


async def socks5_or_http_accept(reader: StreamReader, writer: StreamWriter):
    buf = await reader.read(4096)
    if buf[0] == 5:
        return await socks5_accept(buf, reader, writer)
    else:
        return await http_accept(buf, reader, writer)


# vmess #######################################################################


def vmess_req_pack(uid: UUID, addr: str, port: int) -> Tuple[bytes, bytes, int, bytes]:
    key = random.randbytes(16)
    iv = random.randbytes(16)
    rv = random.getrandbits(8)

    ts = int(time.time())
    ts_bytes = ts.to_bytes(8, "big")

    addr_bytes = addr.encode()
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
        f"!B16s16sBBBBBHBB{alen}s{plen}s",
        1,
        iv,
        key,
        rv,
        1,
        (plen << 4) + 3,
        0,
        1,
        port,
        2,
        alen,
        addr_bytes,
        random.randbytes(plen),
    )
    req += fnv32a(req)

    cipher = Cipher(
        AES(md5(uid.bytes + b"c48619fe-8f02-49e0-b9e9-edf763e17e21").digest()),
        CFB(md5(4 * ts_bytes).digest()),
    )
    encryptor = cipher.encryptor()
    req = encryptor.update(req) + encryptor.finalize()

    auth = HMAC(key=uid.bytes, msg=ts_bytes, digestmod="md5").digest()
    req = auth + req

    return key, iv, rv, req


def vmess_res_unpack(key: bytes, iv: bytes, rv: int, res: bytes):
    cipher = Cipher(AES(key), CFB(iv))
    encryptor = cipher.encryptor()
    res = encryptor.update(res) + encryptor.finalize()
    rrv, opts, cmd, clen = struct.unpack("!BBBB", res)
    if rrv != rv and opts != 0 and cmd != 0 and clen != 0:
        raise struct.error("invalid vmess response")
    return


# copy ########################################################################


async def io_copy(reader: StreamReader, writer: StreamWriter):
    while True:
        buf = await reader.read(4096)
        if len(buf) == 0:
            if writer.can_write_eof():
                writer.write_eof()
            break
        else:
            writer.write(buf)
            await writer.drain()
    return


async def io_copy_raw_vmess(
    reader: StreamReader,
    writer: StreamWriter,
    key: bytes,
    iv: bytes,
    req: bytes,
    rest: bytes,
):
    aesgcm, iv, count = AESGCM(key), iv[2:12], 0
    writer.write(req)
    if rest:
        buf = aesgcm.encrypt(struct.pack("!H", count) + iv, rest, b"")
        buf = struct.pack("!H", len(buf)) + buf
        writer.write(buf)
        count += 1
    await writer.drain()
    while True:
        buf = await reader.read(4096)
        if len(buf) == 0:
            buf = aesgcm.encrypt(struct.pack("!H", count) + iv, b"", b"")
            writer.write(buf)
            if writer.can_write_eof():
                writer.write_eof()
            break
        else:
            buf = aesgcm.encrypt(struct.pack("!H", count) + iv, buf, b"")
            buf = struct.pack("!H", len(buf)) + buf
            writer.write(buf)
            await writer.drain()
            count += 1
    return


async def io_copy_vmess_raw(
    reader: StreamReader, writer: StreamWriter, key: bytes, iv: bytes, rv: int
):
    key, iv = md5(key).digest(), md5(iv).digest()
    buf = await reader.readexactly(4)
    vmess_res_unpack(key, iv, rv, buf)
    aesgcm, iv, count = AESGCM(key), iv[2:12], 0
    eof = False
    while True:
        try:
            buf = await reader.readexactly(2)
            (blen,) = struct.unpack("!H", buf)
            buf = await reader.readexactly(blen)
        except asyncio.IncompleteReadError:
            eof = True
        if eof:
            if writer.can_write_eof():
                writer.write_eof()
            break
        else:
            buf = aesgcm.decrypt(struct.pack("!H", count) + iv, buf, b"")
            writer.write(buf)
            await writer.drain()
            count += 1
    return


# connect #####################################################################


tasks = set()


async def raw_connect(
    reader: StreamReader, writer: StreamWriter, addr: str, port: int, rest: bytes
):
    peer_reader, peer_writer = await asyncio.open_connection(addr, port)
    if rest:
        peer_writer.write(rest)
        await peer_writer.drain()
    task1 = asyncio.create_task(io_copy(reader, peer_writer))
    task2 = asyncio.create_task(io_copy(peer_reader, writer))
    tasks.add(task1)
    tasks.add(task2)
    task1.add_done_callback(tasks.discard)
    task2.add_done_callback(tasks.discard)
    try:
        await asyncio.gather(task1, task2)
    except Exception:
        if not task1.cancelled():
            task1.cancel()
        if not task2.cancelled():
            task2.cancel()
        raise
    return


async def vmess_connect(
    reader: StreamReader,
    writer: StreamWriter,
    addr: str,
    port: int,
    rest: bytes,
    peer: Peer,
):
    peer_reader, peer_writer = await asyncio.open_connection(peer[0][0], peer[0][1])
    key, iv, rv, req = vmess_req_pack(peer[1], addr, port)
    task1 = asyncio.create_task(
        io_copy_raw_vmess(reader, peer_writer, key, iv, req, rest)
    )
    task2 = asyncio.create_task(io_copy_vmess_raw(peer_reader, writer, key, iv, rv))
    tasks.add(task1)
    tasks.add(task2)
    task1.add_done_callback(tasks.discard)
    task2.add_done_callback(tasks.discard)
    try:
        await asyncio.gather(task1, task2)
    except Exception:
        if not task1.cancelled():
            task1.cancel()
        if not task2.cancelled():
            task2.cancel()
        raise
    return
