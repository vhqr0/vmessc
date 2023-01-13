from urllib.parse import urlparse
import argparse
import logging

from uuid import UUID

from .cli import VmessCli
from .client import VmessClient


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--config-file", default="config.json")
    parser.add_argument("-q", "--quick", action="store_true")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("-l", "--local", default="localhost:1080")
    parser.add_argument("-p", "--peer")
    parser.add_argument("-u", "--uid")
    parser.add_argument("-d", "--direction", default="direct")
    parser.add_argument("-r", "--rule-file")
    args = parser.parse_args()

    config_file = args.config_file
    quick = args.quick
    verbose = args.verbose
    local = urlparse("socks5://" + (args.local or ""))
    peer = urlparse("vmess://" + (args.peer or ""))
    uid = UUID(args.uid) if args.uid else None
    direction = args.direction
    rule_file = args.rule_file

    if quick:
        if verbose:
            logging.basicConfig(level=logging.DEBUG)
        client = VmessClient(
            local=(local.hostname, local.port),
            peers=[((peer.hostname, peer.port), uid)],
            direction=direction,
            rule_file=rule_file,
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
