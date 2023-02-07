import time
import socket

from typing_extensions import Self
from uuid import UUID


class VmessNode:
    ps: str
    addr: str
    port: int
    uuid: UUID
    delay: float

    def __init__(self, ps: str, addr: str, port: int, uuid: UUID,
                 delay: float):
        self.ps = ps
        self.addr = addr
        self.port = port
        self.uuid = uuid
        self.delay = delay

    def __str__(self) -> str:
        return f'{self.ps}\t{self.addr}:{self.port}\t{self.delay}'

    @classmethod
    def from_dict(cls, obj: dict) -> Self:
        return cls(ps=str(obj['ps']),
                   addr=str(obj['addr']),
                   port=int(obj['port']),
                   uuid=UUID(str(obj['uuid'])),
                   delay=float(obj['delay']))

    def to_dict(self) -> dict:
        return {
            'ps': self.ps,
            'addr': self.addr,
            'port': self.port,
            'uuid': str(self.uuid),
            'delay': self.delay,
        }

    def ping(self):
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
