from urllib.parse import urlparse
import argparse
import logging

from uuid import UUID

from typing import Optional

from .cli import VmessCli
from .client import VmessClient


class VmessClientQuickRunner(VmessClient):
    def __init__(
        self,
        local: Optional[str],
        peer: Optional[str],
        uid: Optional[str],
        direction: Optional[str],
        rule_file: Optional[str],
    ):
        if uid is None:
            raise TypeError("uid is None")
        localurl = urlparse("socks5://" + (local or ""))
        peerurl = urlparse("vmess://" + (peer or ""))
        super().__init__(
            local=(str(localurl.hostname or ""), localurl.port or 0),
            peers=[((str(peerurl.hostname or ""), peerurl.port or 0), UUID(uid))],
            direction=direction or "direct",
            rule_file=rule_file,
        )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--config-file", default="config.json")
    parser.add_argument("-q", "--quick-run", action="store_true")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("-l", "--local", default="localhost:1080")
    parser.add_argument("-p", "--peer")
    parser.add_argument("-u", "--uid")
    parser.add_argument("-d", "--direction", default="direct")
    parser.add_argument("-r", "--rule-file")
    args = parser.parse_args()

    config_file = args.config_file
    quick_run = args.quick_run
    verbose = args.verbose
    local = args.local
    peer = args.peer
    uid = args.uid
    direction = args.direction
    rule_file = args.rule_file

    if quick_run:
        if verbose:
            logging.basicConfig(level=logging.DEBUG)
        client = VmessClientQuickRunner(
            local=local, peer=peer, uid=uid, direction=direction, rule_file=rule_file
        )
        client.run()
    else:
        cli = VmessCli(config_file=config_file)
        try:
            cli.cmdloop()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
