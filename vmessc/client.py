"""A rule based, load balanced vmess client.

The client is similar to other popular rule based proxy tools, but can
configure more than one peers, and randomly select one when using.

Usage example:

  client = VmessClient(local_addr='0.0.0.0',
                       local_port=1080,
                       peers=[peer1, peer2],
                       direction='direct',
                       rule_file='rule.txt')
  client.run()
"""

import random
from urllib.parse import urlparse
import asyncio
import logging
import argparse

from typing import Optional, List
from uuid import UUID
from asyncio import StreamReader, StreamWriter

from .node import VmessNode
from .rule import Rule, RuleMatcher
from .proxy import ProxyAcceptor, RawConnector
from .vmess import VmessConnector


class VmessClient:
    """Vmess proxy protocol client.

    Run client by calling client.run().

    Args:
        local_addr: Addr to listen.
        local_port: Port to listen.
        peers: A set of peer vmess nodes.
        rule_matcher: Rule matcher.
    """
    local_addr: str
    local_port: int
    peers: List[VmessNode]
    rule_matcher: RuleMatcher

    logger = logging.getLogger('vmess_client')

    def __init__(
        self,
        local_addr: str,
        local_port: int,
        peers: List[VmessNode],
        direction: str = 'direct',
        rule_file: Optional[str] = None,
    ):
        """
        Args:
            local_addr: Addr to listen.
            local_port: Port to listen.
            peers: A set of peer vmess nodes.
            direction: Default rule passed to rule_matcher.
            rule_file: Rule set file path passed to rule_matcher.
        """
        if not peers:
            raise ValueError('no peers specified')

        self.local_addr = local_addr
        self.local_port = local_port
        self.peers = peers
        self.rule_matcher = RuleMatcher(direction=direction,
                                        rule_file=rule_file)

    def run(self):
        """Run client."""
        try:
            asyncio.run(self.start_server())
        except Exception as e:
            self.logger.error('server except %s', e)

    async def start_server(self):
        """Start server."""
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
        """Server callback.

        Args:
            reader: Client reader, accept from start_server as callback args.
            writer: Client writer, accept from start_server as callback args.
        """
        try:
            acceptor = ProxyAcceptor(reader, writer)
            await acceptor.accept()
        except Exception as e:
            self.logger.debug('[except]\twhile accepting: %s', e)
            return

        peer: Optional[VmessNode] = None

        try:
            rule = self.rule_matcher.match(acceptor.addr)
            if rule == Rule.Block:
                self.logger.info('[block]\tconnect to %s:%d', acceptor.addr,
                                 acceptor.port)
                return
            if rule == Rule.Direct:
                self.logger.info('[direct]\tconnect to %s:%d', acceptor.addr,
                                 acceptor.port)
                raw_connector = RawConnector.from_acceptor(acceptor)
                await raw_connector.connect()
            elif rule == Rule.Forward:
                peer, = random.choices(
                    self.peers, weights=[peer.weight for peer in self.peers])
                self.logger.info('[forward]\tconnect to %s:%d via %s',
                                 acceptor.addr, acceptor.port, peer.ps)
                vmess_connector = VmessConnector.from_acceptor(acceptor, peer)
                await vmess_connector.connect()
                peer.weight_increase()
        except Exception as e:
            if peer is not None:
                peer.weight_decrease()
                self.logger.debug(
                    '[except]\twhile connecting to %s:%d via %s: %s',
                    acceptor.addr, acceptor.port, peer.ps, e)
            else:
                self.logger.debug('[except]\twhile connecting to %s:%d: %s',
                                  acceptor.addr, acceptor.port, e)


def main():
    """Main entry to run client with one peer."""
    parser = argparse.ArgumentParser()
    parser.add_argument()
    parser.add_argument('-l', '--local-url', default='http://localhost:1080')
    parser.add_argument('-p', '--peer-url', default='vmess://localhost:443')
    parser.add_argument('-u', '--uuid')
    parser.add_argument('-d', '--direction', default='direct')
    parser.add_argument('-r', '--rule-file')
    args = parser.parse_args()

    local_url = urlparse(args.local_url)
    peer_url = urlparse(args.peer_url)
    uuid = UUID(args.uuid)
    direction = args.direction
    rule_file = args.rule_file

    logging.basicConfig(level='DEBUG')

    peer = VmessNode.from_dict({
        'ps': 'vmessc',
        'addr': peer_url.hostname or 'localhost',
        'port': peer_url.port or 443,
        'uuid': uuid,
        'delay': -1.0,
    })

    client = VmessClient(local_addr=local_url.hostname or 'localhost',
                         local_port=local_url.port or 1080,
                         peers=[peer],
                         direction=direction,
                         rule_file=rule_file)
    client.run()


if __name__ == '__main__':
    main()
