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

from uuid import UUID
from asyncio import StreamReader, StreamWriter

from typing import Tuple

from .types import Peer
from .util import fnv32a

# vmess #######################################################################


def vmess_req_pack(uid: UUID, addr: str,
                   port: int) -> Tuple[bytes, bytes, int, bytes]:
    key = random.randbytes(16)
    iv = random.randbytes(16)
    rv = random.getrandbits(8)

    ts = int(time.time())
    ts_bytes = ts.to_bytes(8, 'big')

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
        f'!B16s16sBBBBBHBB{alen}s{plen}s',
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
        AES(md5(uid.bytes + b'c48619fe-8f02-49e0-b9e9-edf763e17e21').digest()),
        CFB(md5(4 * ts_bytes).digest()),
    )
    encryptor = cipher.encryptor()
    req = encryptor.update(req) + encryptor.finalize()

    auth = HMAC(key=uid.bytes, msg=ts_bytes, digestmod='md5').digest()
    req = auth + req

    return key, iv, rv, req


def vmess_res_unpack(key: bytes, iv: bytes, rv: int, res: bytes):
    cipher = Cipher(AES(key), CFB(iv))
    encryptor = cipher.encryptor()
    res = encryptor.update(res) + encryptor.finalize()
    rrv, opts, cmd, clen = struct.unpack('!BBBB', res)
    if rrv != rv or opts != 0 or cmd != 0 or clen != 0:
        raise struct.error('invalid vmess response')
    return


# copy ########################################################################


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
        buf = aesgcm.encrypt(struct.pack('!H', count) + iv, rest, b'')
        buf = struct.pack('!H', len(buf)) + buf
        writer.write(buf)
        count += 1
    await writer.drain()
    while True:
        buf = await reader.read(4096)
        if len(buf) == 0:
            buf = aesgcm.encrypt(struct.pack('!H', count) + iv, b'', b'')
            writer.write(buf)
            if writer.can_write_eof():
                writer.write_eof()
            break
        else:
            buf = aesgcm.encrypt(struct.pack('!H', count) + iv, buf, b'')
            buf = struct.pack('!H', len(buf)) + buf
            writer.write(buf)
            await writer.drain()
            count += 1
    return


async def io_copy_vmess_raw(reader: StreamReader, writer: StreamWriter,
                            key: bytes, iv: bytes, rv: int):
    key, iv = md5(key).digest(), md5(iv).digest()
    buf = await reader.readexactly(4)
    vmess_res_unpack(key, iv, rv, buf)
    aesgcm, iv, count = AESGCM(key), iv[2:12], 0
    eof = False
    while True:
        try:
            buf = await reader.readexactly(2)
            (blen, ) = struct.unpack('!H', buf)
            buf = await reader.readexactly(blen)
        except asyncio.IncompleteReadError:
            eof = True
        if eof:
            if writer.can_write_eof():
                writer.write_eof()
            break
        else:
            buf = aesgcm.decrypt(struct.pack('!H', count) + iv, buf, b'')
            writer.write(buf)
            await writer.drain()
            count += 1
    return


# connect #####################################################################

tasks = set()


async def vmess_connect(
    reader: StreamReader,
    writer: StreamWriter,
    addr: str,
    port: int,
    rest: bytes,
    peer: Peer,
):
    peer_reader, peer_writer = await asyncio.open_connection(
        peer[0][0], peer[0][1])
    key, iv, rv, req = vmess_req_pack(peer[1], addr, port)
    task1 = asyncio.create_task(
        io_copy_raw_vmess(reader, peer_writer, key, iv, req, rest))
    task2 = asyncio.create_task(
        io_copy_vmess_raw(peer_reader, writer, key, iv, rv))
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
