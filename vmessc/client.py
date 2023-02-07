import random
import logging
import asyncio

from typing import Optional, List
from asyncio import StreamReader, StreamWriter

from .node import VmessNode
from .proxy import ProxyAcceptor, RawConnector
from .vmess import VmessConnector
from .rule import Rule, RuleMatcher


class VmessClient:
    local_addr: str
    local_port: int
    peers: List[VmessNode]
    ruleMatcher: RuleMatcher

    logger = logging.getLogger('vmess_client')

    def __init__(
        self,
        local_addr: str,
        local_port: int,
        peers: List[VmessNode],
        direction: str = 'direct',
        rule_file: Optional[str] = None,
    ):
        self.local_addr = local_addr
        self.local_port = local_port
        self.peers = peers
        self.ruleMatcher = RuleMatcher(direction, rule_file)

    def run(self):
        try:
            asyncio.run(self.start_server())
        except Exception as e:
            self.logger.error('server except %s', e)

    async def start_server(self):
        server = await asyncio.start_server(self.open_connection,
                                            self.local_addr,
                                            self.local_port,
                                            reuse_address=True)
        addrs = ', '.join(str(sock.getsockname()) for sock in server.sockets)
        self.logger.info('server start at %s', addrs)
        async with server:
            await server.serve_forever()

    async def open_connection(self, reader: StreamReader,
                              writer: StreamWriter):
        try:
            acceptor = ProxyAcceptor(reader, writer)
            await acceptor.accept()
        except Exception as e:
            self.logger.debug('[except]\twhile accepting: %s', e)
            return
        try:
            rule = self.ruleMatcher.match(acceptor.addr)
            if rule == Rule.Block:
                self.logger.info('[block]\tconnect to %s:%d', acceptor.addr,
                                 acceptor.port)
                return
            if rule == Rule.Direct:
                self.logger.info('[direct]\tconnect to %s:%d', acceptor.addr,
                                 acceptor.port)
                connector = RawConnector.from_acceptor(acceptor)
                await connector.connect()
            elif rule == Rule.Forward:
                peer = random.choice(self.peers)
                self.logger.info('[forward]\tconnect to %s:%d via %s',
                                 acceptor.addr, acceptor.port, peer.ps)
                connector = VmessConnector.from_acceptor(acceptor, peer)
                await connector.connect()
        except Exception as e:
            self.logger.debug('[except]\twhile connecting to %s:%d: %s',
                              acceptor.addr, acceptor.port, e)
