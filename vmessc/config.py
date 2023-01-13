import os
import time
import re
import base64
import json
from urllib.parse import urlparse
import socket
from concurrent.futures import ThreadPoolExecutor

import requests

from uuid import UUID

from typing import Optional, List

from .types import Peer
from .client import VmessClient


class VmessNode:
    ps: str
    addr: str
    port: int
    uid: str
    delay: float

    def __init__(self, ps: str, addr: str, port: int, uid: str, delay: float):
        self.ps = ps
        self.addr = addr
        self.port = port
        self.uid = uid
        self.delay = delay

    def __str__(self):
        return f"{self.ps} {self.addr} {self.port} {self.delay}"

    def to_dict(self) -> dict:
        return {
            "ps": self.ps,
            "addr": self.addr,
            "port": self.port,
            "uid": self.uid,
            "delay": self.delay,
        }

    def to_peer(self) -> Peer:
        return (self.addr, self.port), UUID(self.uid)

    def ping(self):
        self.delay = -1.0
        try:
            start_time = time.time()
            sock = socket.create_connection((self.addr, self.port), 3)
            sock.close()
            end_time = time.time()
            self.delay = end_time - start_time
        except:
            pass
        print(f"ping {self.ps} {self.delay}")


class VmessConfig:
    config_file: str
    url: Optional[str]
    direction: Optional[str]
    rule_file: Optional[str]
    log_level: Optional[str]
    local_addr: Optional[str]
    nodes: List[VmessNode]

    url_re = re.compile("^([0-9a-zA-Z]+)://(.*)$")

    def __init__(self, config_file: str = "config.json"):
        self.config_file = config_file
        self.url = None
        self.direction = None
        self.rule_file = None
        self.log_level = None
        self.local_addr = None
        self.nodes = []

    def print(self):
        print(f"url: {self.url}")
        print(f"direction: {self.direction}")
        print(f"rule_file: {self.rule_file}")
        print(f"log_level: {self.log_level}")
        print(f"local_addr: {self.local_addr}")
        print("--- nodes ---")
        for idx, node in enumerate(self.nodes):
            print(f"{idx}: {node}")

    def save(self):
        with open(self.config_file, "w") as cf:
            json.dump(self.to_dict(), cf)

    def load(self):
        if not os.path.exists(self.config_file):
            self.direction = "direct"
            self.log_level = "INFO"
            self.local_addr = "localhost:1080"
            return
        with open(self.config_file) as cf:
            data = json.load(cf)
            self.url = data.get("url")
            self.direction = data.get("direction") or "direct"
            self.rule_file = data.get("rule_file")
            self.log_level = data.get("log_level") or "INFO"
            self.local_addr = data.get("local_addr") or "localhost:1080"
            self.nodes = []
            nodes = data.get("nodes")
            if isinstance(nodes, list):
                for node in nodes:
                    self.nodes.append(
                        VmessNode(
                            ps=node["ps"],
                            addr=node["addr"],
                            port=node["port"],
                            uid=node["uid"],
                            delay=node["delay"],
                        )
                    )

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "direction": self.direction,
            "rule_file": self.rule_file,
            "log_level": self.log_level,
            "local_addr": self.local_addr,
            "nodes": [node.to_dict() for node in self.nodes],
        }

    def run(self, node_indexes: List[int]):
        if not node_indexes:
            node_indexes = list(range(len(self.nodes)))
        nodes = [node for index, node in enumerate(self.nodes) if index in node_indexes]
        url = urlparse("socks5://" + (self.local_addr or "localhost:1080"))
        client = VmessClient(
            (url.hostname or "localhost", url.port or 1080),
            [node.to_peer() for node in nodes if node.delay > 0.0],
            self.direction or "direct",
            self.rule_file,
        )
        try:
            client.run()
        except KeyboardInterrupt:
            pass

    def ping(self, node_indexes: List[int]):
        if not node_indexes:
            node_indexes = list(range(len(self.nodes)))
        nodes = [node for index, node in enumerate(self.nodes) if index in node_indexes]
        with ThreadPoolExecutor() as executor:
            executor.map(lambda node: node.ping(), nodes)

    def delete(self, node_indexes: List[int]):
        if not node_indexes:
            node_indexes = list(range(len(self.nodes)))
        nodes = [
            node for index, node in enumerate(self.nodes) if index not in node_indexes
        ]
        self.nodes = nodes

    def fetch(self):
        if self.url is None:
            raise ValueError("url is None")
        res = requests.get(self.url)
        if res.status_code != 200:
            res.raise_for_status()
        data = base64.decodebytes(res.content).decode()
        urls = data.split("\r\n")
        self.nodes = []
        for url in urls:
            re_res = self.url_re.match(url)
            if re_res is None:
                return
            scheme = re_res[1]
            if scheme != "vmess":
                continue
            data = base64.decodebytes(re_res[2].encode()).decode()
            data = json.loads(data)
            if data["net"] != "tcp":
                continue
            self.nodes.append(
                VmessNode(
                    ps=data["ps"],
                    addr=data["add"],
                    port=int(data["port"]),
                    uid=data["id"],
                    delay=-1.0,
                )
            )
