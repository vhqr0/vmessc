"""Vmess node representation.

Provide a serializable class VmessNode to represent a vmess node.
"""

import time
import socket

from typing_extensions import Self
from uuid import UUID


class VmessNode:
    """Represent a vmess node.

    Basic information of a vmess node contains addr, port and uuid.
    We additionally add a readable name: ps, which can extract from
    subscribe, and delay time to connect to this node, while -1 means
    timeout.

    Convert from:
        dict VmessNode.from_dict

    Convert to:
        dict VmessNode.to_dict

    Attributes:
        ps: Readable name.
        addr: Addr of node.
        port: Port of vmess service.
        uuid: Identity to connect to vmess service.
        delay: Time to connect to node, while -1 means timeout.
    """
    ps: str
    addr: str
    port: int
    uuid: UUID
    delay: float

    def __init__(self, ps: str, addr: str, port: int, uuid: UUID,
                 delay: float):
        """
        Args:
            ps: Readable name.
            addr: Addr of node.
            port: Port of vmess service.
            uuid: Identity to connect to vmess service.
            delay: Time to connect to node, while -1 means timeout.
        """
        self.ps = ps
        self.addr = addr
        self.port = port
        self.uuid = uuid
        self.delay = delay

    def __str__(self) -> str:
        return f'{self.ps}\t{self.addr}:{self.port}\t{self.delay}'

    @classmethod
    def from_dict(cls, obj: dict) -> Self:
        """Convert dict to VmessNode.

        Args:
            obj: Dict contains ps, addr, port, uuid and delay.

        Return:
            VmessNode initialized from dict.
        """
        return cls(ps=str(obj['ps']),
                   addr=str(obj['addr']),
                   port=int(obj['port']),
                   uuid=UUID(str(obj['uuid'])),
                   delay=float(obj['delay']))

    def to_dict(self) -> dict:
        """Convert VmessNode to dict.

        Returns:
            Dict initialized from VmessNode.
        """
        return {
            'ps': self.ps,
            'addr': self.addr,
            'port': self.port,
            'uuid': str(self.uuid),
            'delay': self.delay,
        }

    def ping(self):
        """Measure delay time."""
        self.delay = -1.0
        try:
            start_time = time.time()
            sock = socket.create_connection((self.addr, self.port), 3)
            sock.close()
            end_time = time.time()
            self.delay = end_time - start_time
        except Exception:
            pass
        print(f'ping {self.ps}\t{self.delay}')
