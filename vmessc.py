#!/usr/bin/env python3
"""
Implemention of vmess client protocol: https://www.v2ray.com/developer/protocols/vmess.html
and a command line interface to manage subscription, and vmess client startup options.
"""

import asyncio
from concurrent.futures import ThreadPoolExecutor
import socket
import sqlite3
import json
import base64
import uuid
from urllib.parse import urlparse
import time
import random
import re
import struct

from hashlib import md5
from hmac import HMAC

from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import CFB
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import requests

## RuleDB
# db = RuleDB(RULE_PROXY)
# db.connect('dl.db')
# db.match('www.google.com')
# > 2
# db.cache
# > {'google.com': 2,
# >  'www.google.com': 2}

RULE_BLOCK = 1
RULE_PROXY = 2
RULE_DIRECT = 3


class RuleDB:

    def __init__(self, default):
        self.conn = None
        self.cur = None
        self.default = default
        self.cache = dict()

    def connect(self, dbfile):
        self.conn = sqlite3.connect(dbfile)
        self.cur = self.conn.cursor()

    def match(self, domain):
        if not self.conn:
            return self.default
        res = self.cache.get(domain)
        if res:
            return res
        self.cur.execute(f'select rule from data where domain={repr(domain)};')
        res = self.cur.fetchone()
        if res:
            res = res[0]
        if not res:
            pos = domain.find('.')
            if pos > 0:
                res = self.match(domain[pos + 1:])
        if not res:
            res = self.default
        self.cache[domain] = res
        return res

    @classmethod
    def rule2pres(cls, rule):
        return {
            RULE_BLOCK: 'block',
            RULE_PROXY: 'proxy',
            RULE_DIRECT: 'direct',
        }[rule]

    @classmethod
    def pres2rule(cls, pres):
        return {
            'block': RULE_BLOCK,
            'proxy': RULE_PROXY,
            'direct': RULE_DIRECT,
        }[pres]


## socks5_or_http_unpack
# recv and unpack socks5 (start with \x05) or http (or else) format proxy request

ATYPE_IPV4 = 1
ATYPE_IPV6 = 4
ATYPE_DOMAIN = 3


async def socks5_unpack(buf, reader, writer):
    nmeths = buf[1]
    ver, nmeths, meths = struct.unpack(f'!BB{nmeths}s', buf)
    assert ver == 5 and 0 in meths
    writer.write(b'\x05\x00')
    await writer.drain()
    buf = await reader.read(4096)
    atype = buf[3]
    assert atype in (ATYPE_IPV4, ATYPE_IPV6, ATYPE_DOMAIN)
    if atype == ATYPE_IPV4:
        ver, cmd, rsv, atype, addr, port = struct.unpack('!BBBB4sH', buf)
        addr = socket.inet_ntop(socket.AF_INET, addr)
    elif atype == ATYPE_IPV6:
        ver, cmd, rsv, atype, addr, port = struct.unpack('!BBBB16sH', buf)
        addr = socket.inet_ntop(socket.AF_INET6, addr)
    else:
        alen = buf[4]
        ver, cmd, rsv, atype, alen, addr, port = struct.unpack(
            f'!BBBBB{alen}sH', buf)
        addr = addr.decode()
    assert ver == 5 and cmd == 1 and rsv == 0
    writer.write(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')
    await writer.drain()
    return addr, port


http_re1 = re.compile(r'^(\w+) [^ ]+ (HTTP/[^ \r\n]+)\r\n')
http_re2 = re.compile(
    r'\r\nHost: ([^ :\[\]\r\n]+|\[[:0-9a-fA-F]+\])(:([0-9]+))?\r\n')


async def http_unpack(buf, reader, writer):
    pos = buf.find(b'\r\n\r\n')
    assert pos > 0
    header = buf[:pos + 2].decode()
    rest = buf[pos + 4:]
    res1 = http_re1.search(header)
    res2 = http_re2.search(header)
    assert res1 and res2
    method = res1[1]
    version = res1[2]
    addr = res2[1]
    port = res2[3]
    addr = addr if addr[0] != '[' else addr[1:-1]
    port = int(port) if port else 80
    if method == 'CONNECT':
        writer.write(
            f'{version} 200 Connection Established\r\nConnection: close\r\n\r\n'
            .encode())
        await writer.drain()
    else:
        rest = '\r\n'.join(
            h for h in header.split('\r\n')
            if not h.startswith('Proxy-')).encode() + b'\r\n' + rest
    return addr, port, rest


async def socks5_or_http_unpack(reader, writer):
    buf = await reader.read(4096)
    if buf[0] == 5:
        addr, port = await socks5_unpack(buf, reader, writer)
        return addr, port, b''
    else:
        return await http_unpack(buf, reader, writer)


## vmess_connect
# match ruledb and proxy local(raw)/remote(vmess)


async def proxy(reader, writer):
    while True:
        buf = await reader.read(4096)
        if len(buf) == 0:
            if writer.can_write_eof():
                writer.write_eof()
            break
        else:
            writer.write(buf)
            await writer.drain()


def fnv32a(data):
    hval = 0x811c9dc5
    fnv_32_prime = 0x01000193
    for c in data:
        hval = ((hval ^ c) * fnv_32_prime) & 0xffffffff
    return hval.to_bytes(4, 'big')


def vmess_req_pack(uid, addr, port):

    key = random.randbytes(16)
    iv = random.randbytes(16)
    rv = random.getrandbits(8)

    ts = int(time.time())
    ts_bytes = ts.to_bytes(8, 'big')
    auth = HMAC(key=uid, msg=ts_bytes, digestmod='md5').digest()

    addr = addr.encode()
    alen = len(addr)
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
    req = struct.pack(f'!B16s16sBBBBBHBB{alen}s{plen}s', 1, iv, key, rv, 1,
                      (plen << 4) + 3, 0, 1, port, 2, alen, addr,
                      random.randbytes(plen))
    req += fnv32a(req)

    cipher = Cipher(
        AES(md5(uid + b'c48619fe-8f02-49e0-b9e9-edf763e17e21').digest()),
        CFB(md5(4 * ts_bytes).digest()))
    encryptor = cipher.encryptor()
    req = encryptor.update(req) + encryptor.finalize()

    return key, iv, rv, auth + req


def vmess_res_unpack(key, iv, rv, res):
    cipher = Cipher(AES(key), CFB(iv))
    encryptor = cipher.encryptor()
    res = encryptor.update(res) + encryptor.finalize()
    v, opts, cmd, clen = struct.unpack('!BBBB', res)
    assert v == rv and opts == 0 and cmd == 0 and clen == 0


def vmess_data_pack(aesgcm, iv, count, data):
    iv = struct.pack('!H', count) + iv
    data = aesgcm.encrypt(iv, data, b'')
    return struct.pack('!H', len(data)) + data


def vmess_data_unpack(aesgcm, iv, count, data):
    iv = struct.pack('!H', count) + iv
    data = aesgcm.decrypt(iv, data, b'')
    return data


async def proxy_raw2vmess(reader, writer, data, rest, key, iv):
    aesgcm, iv, count = AESGCM(key), iv[2:12], 0
    writer.write(data)
    if rest:
        writer.write(vmess_data_pack(aesgcm, iv, count, rest))
        count += 1
    await writer.drain()
    while True:
        buf = await reader.read(4096)
        if len(buf) == 0:
            if writer.can_write_eof():
                writer.write_eof()
            break
        else:
            writer.write(vmess_data_pack(aesgcm, iv, count, buf))
            count += 1
            await writer.drain()


async def proxy_vmess2raw(reader, writer, key, iv, rv):
    key, iv = md5(key).digest(), md5(iv).digest()
    buf = await reader.readexactly(4)
    vmess_res_unpack(key, iv, rv, buf)
    aesgcm, iv, count = AESGCM(key), iv[2:12], 0
    eof = False
    while True:
        try:
            buf = await reader.readexactly(2)
            dlen, = struct.unpack('!H', buf)
            buf = await reader.readexactly(dlen)
        except asyncio.IncompleteReadError:
            eof = True
        if eof:
            if writer.can_write_eof():
                writer.write_eof()
            break
        else:
            writer.write(vmess_data_unpack(aesgcm, iv, count, buf))
            count += 1
            await writer.drain()


async def vmess_connect(in_reader, in_writer, out_addr, rdb, uid, addr, port,
                        rest):
    peername = in_writer.get_extra_info('peername')[:2]
    rule = rdb.match(addr)
    if rule not in (RULE_PROXY, RULE_DIRECT):
        print(f'{peername} <=> {(addr, port)} [block]')
        in_writer.close()
        await in_writer.wait_closed()
        return
    elif rule == RULE_PROXY:
        print(f'{peername} <=> {(addr, port)} [proxy]')
        out_reader, out_writer = await asyncio.open_connection(
            out_addr[0], out_addr[1])
        key, iv, rv, data = vmess_req_pack(uid, addr, port)
        await asyncio.gather(
            proxy_raw2vmess(in_reader, out_writer, data, rest, key, iv),
            proxy_vmess2raw(out_reader, in_writer, key, iv, rv))
        return
    elif rule == RULE_DIRECT:
        print(f'{peername} <=> {(addr, port)} [direct]')
        out_reader, out_writer = await asyncio.open_connection(addr, port)
        if rest:
            out_writer.write(rest)
            await out_writer.drain()
        await asyncio.gather(proxy(in_reader, out_writer),
                             proxy(out_reader, in_writer))


## vmessc


class vmessc:

    def __init__(self, in_addr, out_addr, uid, rule_dbfile, rule_default,
                 debug):
        self.in_addr = in_addr
        self.out_addr = out_addr
        self.uid = uuid.UUID(uid).bytes
        self.rdb = RuleDB(rule_default)
        if rule_dbfile:
            self.rdb.connect(rule_dbfile)
        self.debug = debug

    def run(self):
        asyncio.run(self.start_server())

    async def start_server(self):
        server = await asyncio.start_server(self.open_connection,
                                            self.in_addr[0],
                                            self.in_addr[1],
                                            reuse_address=True)
        addrs = ', '.join(str(sock.getsockname()) for sock in server.sockets)
        print(f'server start at {addrs}')
        async with server:
            await server.serve_forever()

    async def open_connection(self, in_reader, in_writer):
        try:
            addr, port, rest = await socks5_or_http_unpack(
                in_reader, in_writer)
            await vmess_connect(in_reader, in_writer, self.out_addr, self.rdb,
                                self.uid, addr, port, rest)
        except:
            if self.debug:
                raise


## cli


class vmesscli:

    def __init__(self, datafile):
        self.datafile = datafile
        self.data = dict()
        try:
            self.data = json.load(open(self.datafile))
        except:
            pass

    def dump(self):
        json.dump(self.data, open(self.datafile, 'w'))

    def list(self, _args):
        url = self.data.get('url')
        addr = self.data.get('addr')
        rule_dbfile = self.data.get('rule_dbfile')
        rule_default = self.data.get('rule_default')
        debug = self.data.get('debug')
        nodes = self.data.get('nodes')
        print(f'url:\t{url}')
        print(f'addr:\t{addr}')
        print(
            f'rule:\t{rule_dbfile} {RuleDB.rule2pres(rule_default or RULE_PROXY)}'
        )
        print(f'debug:\t{debug}')
        print(f'id\tps\turl\tdelay')
        if nodes:
            for i, node in enumerate(nodes):
                ps = node['ps']
                scheme = node['scheme']
                addr = node['add']
                port = node['port']
                delay = node['delay']
                print(f'{i}\t{ps}\t{scheme}://{addr}:{port}\t{delay}')

    def fetch(self, args):
        url = self.data.get('url')
        proxies = {'http': args[0], 'https': args[0]} if args else {}
        res = requests.get(url, proxies=proxies)
        assert res.status_code == 200
        data = base64.decodebytes(res.content).decode()
        urls = data.split('\r\n')
        nodes = []
        url_re = re.compile('^([0-9a-zA-Z]+)://(.*)$')
        for url in urls:
            re_res = url_re.match(url)
            if not re_res:
                continue
            scheme = re_res[1]
            data = base64.decodebytes(re_res[2].encode()).decode()
            data = json.loads(data)
            data['scheme'] = scheme
            data['delay'] = 'none'
            nodes.append(data)
        self.data['nodes'] = nodes
        self.dump()

    def delete(self, args):
        nids = list(int(i) for i in args)
        nodes = self.data.get('nodes')
        nnodes = []
        if nodes:
            for i, node in enumerate(nodes):
                if i not in nids:
                    nnodes.append(node)
        self.data['nodes'] = nnodes
        self.dump()

    def ping(self, args):

        def test_delay(addr):
            try:
                t1 = time.time()
                sock = socket.create_connection(addr, 3)
                sock.close()
                t2 = time.time()
                delay = t2 - t1
                print(f'{addr}: {delay}')
                return delay
            except:
                print(f'{addr}: timeout')
                return 'timeout'

        nodes = self.data.get('nodes')
        nids = list(int(i) for i in args) if args else range(len(nodes))
        nids = list(i for i in nids if i < len(nodes))
        addrs = [(nodes[i]['add'], int(nodes[i]['port'])) for i in nids]
        with ThreadPoolExecutor() as executor:
            for nid, delay in zip(nids, executor.map(test_delay, addrs)):
                nodes[nid]['delay'] = delay
        self.dump()

    def seturl(self, args):
        self.data['url'] = args[0] if args else None
        self.dump()

    def setaddr(self, args):
        self.data['addr'] = args[0] if args else '0.0.0.0:1080'
        self.dump()

    def setrule(self, args):
        self.data['rule_dbfile'] = args[0] if args else None
        self.data['rule_default'] = RuleDB.pres2rule(
            args[1]) if len(args) > 1 else RULE_PROXY
        self.dump()

    def setdebug(self, _args):
        self.data['debug'] = not self.data.get('debug')
        self.dump()

    def run_vmessc(self, args):
        nodes = self.data.get('nodes')
        node = nodes[int(args[0])] if args else random.choice(nodes)
        in_url = urlparse('//' + (self.data.get('addr') or ''))
        in_addr = (in_url.hostname or '0.0.0.0', in_url.port or 1080)
        out_addr = (node['add'], int(node['port']))
        uid = node['id']
        rule_dbfile = self.data.get('rule_dbfile')
        rule_default = self.data.get('rule_default') or RULE_PROXY
        debug = self.data.get('debug')
        try:
            vmessc(in_addr, out_addr, uid, rule_dbfile, rule_default,
                   debug).run()
        except KeyboardInterrupt:
            pass

    def run(self):
        self.list([])
        while True:
            cmd = input(
                'l(ist) f(etch) d(elete) p(ing) r(un) -u(rl) -a(ddr) -r(ule) -d(ebug): '
            ).split()
            if cmd[0] == 'l':
                self.list(cmd[1:])
            elif cmd[0] == 'f':
                self.fetch(cmd[1:])
                self.list([])
            elif cmd[0] == 'd':
                self.delete(cmd[1:])
                self.list([])
            elif cmd[0] == 'p':
                self.ping(cmd[1:])
                self.list([])
            elif cmd[0] == 'r':
                self.run_vmessc(cmd[1:])
            elif cmd[0] == '-u':
                self.seturl(cmd[1:])
            elif cmd[0] == '-a':
                self.setaddr(cmd[1:])
            elif cmd[0] == '-r':
                self.setrule(cmd[1:])
            elif cmd[0] == '-d':
                self.setdebug(cmd[1:])
            else:
                print(f'unknown command: {cmd[0]}')


## main


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--config', default='config.json')
    args = parser.parse_args()
    vmesscli(args.config).run()


if __name__ == '__main__':
    main()
