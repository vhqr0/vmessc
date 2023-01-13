import random
import functools
import logging

import asyncio

from enum import Enum
from asyncio import StreamReader, StreamWriter

from typing import Optional, Dict, List

from .types import Addr, Peer
from .util import get_super_domain
from .protocol import socks5_accept, raw_connect, vmess_connect


class Rule(Enum):
    Block = 1
    Direct = 2
    Forward = 3

    def __str__(self):
        match self:
            case self.Block:
                return "block"
            case self.Direct:
                return "direct"
            case self.Forward:
                return "forward"
        return "invalid_rule"


# TODO: use @classmethod, resolve type hinting problem
def rule_from_string(s: str) -> Rule:
    match s.lower():
        case "block":
            return Rule.Block
        case "direct":
            return Rule.Direct
        case "forward":
            return Rule.Forward
        case _:
            raise ValueError(f"invalid rule string: {s}")


class VmessClient:
    local: Addr
    peers: List[Peer]
    direction: Rule
    rules: Optional[Dict[str, Rule]]

    logger = logging.getLogger("vmess_client")

    def __init__(
        self,
        local: Addr,
        peers: List[Peer],
        direction: str = "direct",
        rule_file: Optional[str] = None,
    ):
        self.local = local
        self.peers = peers
        self.direction = rule_from_string(direction)
        self.rules = self.load_rule_file(rule_file) if rule_file else None

    def load_rule_file(self, rule_file: str):
        rules = dict()
        with open(rule_file) as rf:
            for line in rf:
                line = line.strip()
                if len(line) == 0 or line[0] == "#":  # void or comment line
                    continue
                tokens = line.split()
                if len(tokens) != 2:  # invalid line
                    raise ValueError(f"invalid rule: {line}")
                rule = rule_from_string(tokens[0])  # may raise ValueError
                domain = tokens[1]
                if domain in rules:
                    # previous rule has higher priority
                    continue
                rules[domain] = rule
        return rules

    @functools.cache
    def match_rule(self, domain: str) -> Rule:
        if self.rules is None:  # no rules
            return self.direction
        rule = self.rules.get(domain)
        if rule is not None:  # match domain
            return rule
        super_domain = get_super_domain(domain)
        if super_domain is not None:  # recursive match super domain
            return self.match_rule(super_domain)
        return self.direction  # use default rule

    def run(self):
        try:
            asyncio.run(self.start_server())
        except Exception as e:
            self.logger.error("server except %s", e)
        except KeyboardInterrupt:
            self.logger.info("keyboard quit")

    async def start_server(self):
        server = await asyncio.start_server(
            self.open_connection, self.local[0], self.local[1], reuse_address=True
        )
        addrs = ", ".join(str(sock.getsockname()) for sock in server.sockets)
        self.logger.info("server start at %s", addrs)
        async with server:
            await server.serve_forever()

    async def open_connection(self, reader: StreamReader, writer: StreamWriter):
        try:
            addr, port = await socks5_accept(reader, writer)
            rule = self.match_rule(addr)
            self.logger.info("connect to %s %d %s", addr, port, rule)
            match rule:
                case Rule.Block:
                    return
                case Rule.Direct:
                    await raw_connect(reader, writer, addr, port)
                case Rule.Forward:
                    await vmess_connect(
                        reader, writer, addr, port, random.choice(self.peers)
                    )
        except Exception as e:
            self.logger.debug("except %s", e)
