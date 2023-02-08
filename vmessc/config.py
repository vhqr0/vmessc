"""Subscribe and client config manager.

Easy to fetch and manage subscribed-ed vmess nodes, and start client
from a config file.

Subscribe format:
https://github.com/2dust/v2rayN/wiki/%E5%88%86%E4%BA%AB%E9%93%BE%E6%8E%A5%E6%A0%BC%E5%BC%8F%E8%AF%B4%E6%98%8E(ver-2)

Config example:

  {
    "fetch_url": "https://example.net",
    "direction": "direct",
    "rule_file": "rule.txt",
    "log_level": "INFO",
    "local_url": "http://localhost:1080",
    "nodes": [
      {
        "ps": "peer1",
        "addr": "peer1.net",
        "port": "80",
        "uuid": "...",
        "delay": 0.4
      },
      {
        "ps": "peer2",
        "addr": "peer2.net",
        "port": "443",
        "uuid": "...",
        "delay": 0.5
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
import base64
import json
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor

import requests

from typing import Optional, List
from urllib.parse import ParseResult as URL

from .node import VmessNode
from .client import VmessClient


class VmessConfig:
    """Vmess client config manager.

    Attributes:
        config_file: Persistent configure file path.
        fetch_url: URL to fetch subscribed-ed vmess nodes.
        direction: Default rule passed to ruleMatcher.
        rule_file: Rule set file path passed to ruleMatcher.
        log_level: Logging level, 'DEBUG', 'INFO', 'WARNING', etc.
        local_url: Local addr:port to listen.
        nodes: A set of peer vmess nodes.
    """
    config_file: str
    fetch_url: Optional[URL]
    direction: Optional[str]
    rule_file: Optional[str]
    log_level: Optional[str]
    local_url: Optional[URL]
    nodes: List[VmessNode]

    url_re = re.compile('^([0-9a-zA-Z]+)://(.*)$')

    def __init__(self, config_file: str = 'config.json'):
        """
        Args:
            config_file: Persistent configure file path.
        """
        self.config_file = config_file
        self.fetch_url = None
        self.direction = None
        self.rule_file = None
        self.log_level = None
        self.local_url = None
        self.nodes = []

    def print(self):
        """Print config."""
        print(f'fetch_url:\t{self.fetch_url.geturl()}')
        print(f'direction:\t{self.direction}')
        print(f'rule_file:\t{self.rule_file}')
        print(f'log_level:\t{self.log_level}')
        print(f'local_url:\t{self.local_url.geturl()}')
        print('--- nodes ---')
        for index, node in enumerate(self.nodes):
            print(f'{index}: {node}')

    def save(self):
        """Save config."""
        with open(self.config_file, 'w') as cf:
            json.dump(self.to_dict(), cf)

    def load(self):
        """Load config."""
        if not os.path.exists(self.config_file):
            self.direction = 'direct'
            self.log_level = 'INFO'
            self.local_url = urlparse('http://localhost:1080')
            return
        with open(self.config_file) as cf:
            data = json.load(cf)
            self.fetch_url = urlparse(data.get('fetch_url') or 'http:')
            self.direction = data.get('direction') or 'direct'
            self.rule_file = data.get('rule_file')
            self.log_level = data.get('log_level') or 'INFO'
            self.local_url = urlparse(data.get('local_url') or 'http:')
            self.nodes = []
            nodes = data.get('nodes')
            if isinstance(nodes, list):
                self.nodes = [VmessNode.from_dict(node) for node in nodes]

    def to_dict(self) -> dict:
        """Convert VmessConfig to dict.

        Returns:
            Dict initialized from VmessConfig.
        """
        return {
            'fetch_url': self.fetch_url.geturl(),
            'direction': self.direction,
            'rule_file': self.rule_file,
            'log_level': self.log_level,
            'local_url': self.local_url.geturl(),
            'nodes': [node.to_dict() for node in self.nodes],
        }

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

    def run(self, node_indexes: List[int]):
        """Run client.

        Args:
            node_indexes: See get_nodes, nodes to use as client peers.
        """
        nodes = self.get_nodes(node_indexes)
        client = VmessClient(
            local_addr=self.local_url.hostname or 'localhost',
            local_port=self.local_url.port or 1080,
            peers=[node for node in nodes if node.delay > 0.0],
            direction=self.direction or 'direct',
            rule_file=self.rule_file,
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

        Args:
            proxy: Proxy to use while fetching.
        """
        if self.fetch_url.hostname is None:
            raise ValueError('invalid fetch url')
        proxies = {}
        if proxy is not None:
            proxies = {'http': proxy, 'https': proxy}
        res = requests.get(self.fetch_url.geturl(), proxies=proxies)
        if res.status_code != 200:
            res.raise_for_status()
        data = base64.decodebytes(res.content).decode()
        urls = data.split('\r\n')
        self.nodes = []
        for url in urls:
            re_res = self.url_re.match(url)
            if re_res is None:
                return
            scheme = re_res[1]
            if scheme != 'vmess':
                continue
            data = base64.decodebytes(re_res[2].encode()).decode()
            data = json.loads(data)
            if data['net'] != 'tcp':
                continue
            self.nodes.append(
                VmessNode.from_dict({
                    'ps': data['ps'],
                    'addr': data['add'],
                    'port': data['port'],
                    'uuid': data['id'],
                    'delay': -1.0,
                }))
