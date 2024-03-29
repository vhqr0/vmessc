"""Subscribe and client config manager.

Easy to manage subscribed vmess nodes and start client, using a config file.

Config example:

  {
    "fetch_url": "https://example.net",
    "local_url": "http://localhost:1080",
    "direction": "direct",
    "rule_file": "rule.txt",
    "log_level": "INFO",
    "log_format": "%(asctime)s %(name)s %(levelname)s %(message)s",
    "log_datefmt": "%y-%m-%d %H:%M:%S",
    "nodes": [
      {
        "name": "peer1",
        "addr": "peer1.net",
        "port": "80",
        "uuid": "...",
        "delay": 0.4,
        "weight": 20.0
      },
      {
        "name": "peer2",
        "addr": "peer2.net",
        "port": "443",
        "uuid": "...",
        "delay": 0.5,
        "weight": 10.0
      },
    ]
  }

Usage example:

  config = VmessConfig(config_file='config.json')
  config.load()
  config.run()
"""

import os
import re
import json
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor
import logging

from typing import Optional, List
from urllib.parse import ParseResult as URL

from .defaults import (
    CONFIG_FILE,
    RULE_FILE,
    DIRECTION,
    LOCAL_URL,
    LOCAL_ADDR,
    LOCAL_PORT,
    FETCH_URL,
    LOG_LEVEL,
    LOG_FORMAT,
    LOG_DATEFMT,
)
from .node import VmessNode
from .client import VmessClient


class VmessConfig:
    """Vmess client config manager.

    Attributes:
        config_file: Persistent configure file path.
        fetch_url: URL to fetch subscribed-ed vmess nodes.
        local_url: Local addr:port to listen.
        direction: Default rule passed to rule_matcher.
        rule_file: Rule set file path passed to rule_matcher.
        log_level: Logging level, 'DEBUG', 'INFO', 'WARNING', etc.
        log_format: Logging format, see logging.
        log_datefmt: Logging date format ,see logging.
        nodes: A set of peer vmess nodes.
    """
    config_file: str
    fetch_url: URL
    local_url: URL
    direction: Optional[str]
    rule_file: Optional[str]
    log_level: Optional[str]
    log_format: Optional[str]
    log_datefmt: Optional[str]
    nodes: List[VmessNode]

    fetch_url_re = re.compile('^([0-9a-zA-Z]+)://(.*)$')

    def __init__(self, config_file: str = CONFIG_FILE):
        """
        Args:
            config_file: Persistent configure file path.
        """
        self.config_file = config_file
        self.fetch_url = urlparse('http:')
        self.local_url = urlparse('http:')
        self.direction = None
        self.rule_file = None
        self.log_level = None
        self.log_format = None
        self.log_datefmt = None
        self.nodes = []

    def print(self):
        """Print config."""
        print(f'fetch_url:\t{self.fetch_url.geturl()}')
        print(f'local_url:\t{self.local_url.geturl()}')
        print(f'direction:\t{self.direction}')
        print(f'rule_file:\t{self.rule_file}')
        print(f'log_level:\t{self.log_level}')
        print(f'log_format:\t{self.log_format}')
        print(f'log_datefmt:\t{self.log_datefmt}')
        print('--- beg nodes ---')
        for index, node in enumerate(self.nodes):
            node.print(index)
        print('--- end nodes ---')

    def save(self):
        """Save config."""
        data = {
            'fetch_url': self.fetch_url.geturl(),
            'local_url': self.local_url.geturl(),
            'direction': self.direction,
            'rule_file': self.rule_file,
            'log_level': self.log_level,
            'log_format': self.log_format,
            'log_datefmt': self.log_datefmt,
            'nodes': [node.to_dict() for node in self.nodes],
        }
        with open(self.config_file, 'w') as cf:
            json.dump(data, cf)

    def load(self):
        """Load config."""
        if not os.path.exists(self.config_file):
            self.fetch_url = urlparse(FETCH_URL)
            self.local_url = urlparse(LOCAL_URL)
            self.direction = DIRECTION
            self.log_level = LOG_LEVEL
            self.log_format = LOG_FORMAT
            self.log_datefmt = LOG_DATEFMT
            return
        with open(self.config_file) as cf:
            data = json.load(cf)
            self.fetch_url = urlparse(data.get('fetch_url') or FETCH_URL)
            self.local_url = urlparse(data.get('local_url') or LOCAL_URL)
            self.direction = data.get('direction') or DIRECTION
            self.rule_file = data.get('rule_file') or RULE_FILE
            self.log_level = data.get('log_level') or LOG_LEVEL
            self.log_format = data.get('log_format') or LOG_FORMAT
            self.log_datefmt = data.get('log_datefmt') or LOG_DATEFMT
            self.nodes = []
            nodes = data.get('nodes')
            if isinstance(nodes, list):
                self.nodes = [VmessNode.from_dict(node) for node in nodes]

    def get_nodes(self,
                  node_indexes: List[int],
                  exclusive: bool = False) -> List[VmessNode]:
        """Get target nodes.

        Args:
            node_indexes: target node indexes, empty for all.
            exclusive: toggle target and others.
        """
        if not node_indexes:
            node_indexes = list(range(len(self.nodes)))

        def pred(index: int) -> bool:
            if exclusive:
                return index not in node_indexes
            else:
                return index in node_indexes

        nodes = [node for index, node in enumerate(self.nodes) if pred(index)]
        return nodes

    def logging_config(self):
        logging.basicConfig(level=self.log_level,
                            format=self.log_format,
                            datefmt=self.log_datefmt)

    def run(self, node_indexes: List[int]):
        """Run client.

        Args:
            node_indexes: See get_nodes, nodes to use as client peers.
        """
        nodes = self.get_nodes(node_indexes)
        client = VmessClient(
            local_addr=self.local_url.hostname or LOCAL_ADDR,
            local_port=self.local_url.port or LOCAL_PORT,
            peers=nodes,
            direction=self.direction or DIRECTION,
            rule_file=self.rule_file or RULE_FILE,
        )
        client.run()

    def delete(self, node_indexes: List[int]):
        """Delete nodes.

        Args:
            node_indexes: See get_nodes, nodes to delete.
        """
        nodes = self.get_nodes(node_indexes, exclusive=True)
        self.nodes = nodes

    def ping(self, node_indexes: List[int]):
        """Ping nodes.

        Args:
            node_indexes: See get_nodes, nodes to ping.
        """
        nodes = self.get_nodes(node_indexes)
        with ThreadPoolExecutor() as executor:
            executor.map(lambda node: node.ping(), nodes)

    def fetch(self, proxy: Optional[str] = None):
        """Fetch subscribed-ed nodes.

        Notice that fetch from https url via http proxy have some
        problems, socks5h is recommended.

        Args:
            proxy: Proxy to use while fetching.
        """
        proxies = {}
        if proxy is not None:
            proxies = {'http': proxy, 'https': proxy}
        self.nodes = VmessNode.fetch(self.fetch_url.geturl(), proxies=proxies)
