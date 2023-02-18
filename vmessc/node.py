"""Vmess node representation.

Subscribe format:
  https://github.com/2dust/v2rayN/wiki/%E5%88%86%E4%BA%AB%E9%93%BE%E6%8E%A5%E6%A0%BC%E5%BC%8F%E8%AF%B4%E6%98%8E(ver-2)

Provide a serializable and fetchable vmess node class.
"""

import time
import re
import functools
import hashlib
import base64
import json
import socket

import requests

from typing_extensions import Self
from typing import List
from uuid import UUID

from .defaults import (
    WEIGHT_INITIAL,
    WEIGHT_MINIMAL,
    WEIGHT_MAXIMAL,
    WEIGHT_INCREASE_STEP,
    WEIGHT_DECREASE_STEP,
)


class VmessNode:
    """Represent a vmess node.

    Basic information of a vmess node contains addr, port and uuid.
    We additionally add a readable name, which can extract from subscribe,
    and delay time to connect to this node, while -1 means timeout.

    Convert from:
        dict VmessNode.from_dict

    Convert to:
        dict VmessNode.to_dict

    Attributes:
        name: Readable name.
        addr: Addr of node.
        port: Port of vmess service.
        uuid: Identity to connect to vmess service.
        delay: Time to connect to node, while -1 means timeout.
        weight: Dynamicly updated weight to discard unworked nodes.
    """
    name: str
    addr: str
    port: int
    uuid: UUID
    delay: float
    weight: float

    REQ_KEY_SUFFIX = b'c48619fe-8f02-49e0-b9e9-edf763e17e21'

    fetch_url_re = re.compile('^([0-9a-zA-Z]+)://(.*)$')

    def __init__(self,
                 name: str,
                 addr: str,
                 port: int,
                 uuid: UUID,
                 delay: float,
                 weight: float = WEIGHT_INITIAL):
        """
        Args:
            name: Readable name.
            addr: Addr of node.
            port: Port of vmess service.
            uuid: Identity to connect to vmess service.
            delay: Time to connect to node, while -1 means timeout.
            weight: Dynamicly updated weight to discard unworked nodes.
        """
        self.name = name
        self.addr = addr
        self.port = port
        self.uuid = uuid
        self.delay = delay
        self.weight = weight

    @functools.cached_property
    def req_key(self) -> bytes:
        h = hashlib.md5()
        h.update(self.uuid.bytes)
        h.update(self.REQ_KEY_SUFFIX)
        return h.digest()

    def __str__(self) -> str:
        return f'{self.name} W{int(self.weight)}'

    def print(self, index):
        """Print node."""
        print(f'{index}:\t{self}\t{self.addr}:{self.port}\t{self.delay}')

    def to_dict(self) -> dict:
        """Convert VmessNode to dict.

        Returns:
            Dict initialized from VmessNode.
        """
        return {
            'name': self.name,
            'addr': self.addr,
            'port': self.port,
            'uuid': str(self.uuid),
            'delay': self.delay,
            'weight': self.weight,
        }

    @classmethod
    def from_dict(cls, obj: dict) -> Self:
        """Convert dict to VmessNode.

        Args:
            obj: Dict contains name, addr, port, uuid, delay and weight.

        Return:
            VmessNode initialized from dict.
        """
        return cls(name=str(obj['name']),
                   addr=str(obj['addr']),
                   port=int(obj['port']),
                   uuid=UUID(str(obj['uuid'])),
                   delay=float(obj['delay']),
                   weight=float(obj['weight']))

    @classmethod
    def fetch(cls, *args, **kwargs) -> List[Self]:
        """Fetch subscribed vmess nodes.

        Args:
            args, kwargs see requests.get.

        Return:
            A list of vmess nodes.
        """
        res = requests.get(*args, **kwargs)
        if res.status_code != 200:
            res.raise_for_status()
        content = base64.decodebytes(res.content).decode()
        urls = content.split('\r\n')

        nodes = []
        for url in urls:
            re_res = cls.fetch_url_re.match(url)
            if re_res is None or re_res[1] != 'vmess':
                continue
            content = base64.decodebytes(re_res[2].encode()).decode()
            data = json.loads(content)
            if data['net'] != 'tcp':
                continue
            nodes.append(
                cls.from_dict({
                    'name': data['ps'],
                    'addr': data['add'],
                    'port': data['port'],
                    'uuid': data['uuid'],
                    'delay': -1.0,
                    'weight': WEIGHT_INITIAL,
                }))

        return nodes

    def weight_increase(self):
        """Increase weight.

        Called when a request was handled successfully."""
        self.weight = min(self.weight + WEIGHT_INCREASE_STEP, WEIGHT_MAXIMAL)

    def weight_decrease(self):
        """Decrease weight.

        Called when a exception was raised while handling requests."""
        self.weight = max(self.weight - WEIGHT_DECREASE_STEP, WEIGHT_MINIMAL)

    def ping(self):
        """Measure delay time."""
        self.delay = -1.0
        self.weight = -1.0
        try:
            start_time = time.time()
            sock = socket.create_connection((self.addr, self.port), 3)
            sock.close()
            end_time = time.time()
            self.delay = end_time - start_time
            self.weight = WEIGHT_INITIAL
        except Exception:
            pass
        print(f'ping {self}\t{self.delay}')
