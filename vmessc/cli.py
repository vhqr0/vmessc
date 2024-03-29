"""Vmess client command line interface.

Call VmessConfig methods in command line with completion.

Usage example:

  cli = VmessCli(config_file='config.json')
  cli.cmdloop()
"""

from urllib.parse import urlparse
import argparse

from typing import List
from cmd import Cmd

from .defaults import (
    CONFIG_FILE,
)
from .config import VmessConfig


class VmessCli(Cmd):
    """Vmess client command line interface.

    Attributes:
        config: Client config manager.
        keys: Set command completion keywords.
    """
    config: VmessConfig
    keys: List[str]

    keys = ['fetch_url', 'local_url', 'direction', 'rule_file', 'log_level']

    intro = 'Welcome to vmess cli. Type help or ? to list commands.\n'
    prompt = 'vmess cli $ '

    def __init__(self, config_file: str = CONFIG_FILE):
        """
        Args:
            config_file: Config file path passed to config.
        """
        super().__init__()
        self.config = VmessConfig(config_file=config_file)
        self.config.load()

    def do_EOF(self, args: str):
        """Handle C-d as C-c."""
        raise KeyboardInterrupt

    def do_set(self, args: str):
        """Do set."""
        try:
            k, v = args.split(maxsplit=1)
            if k == 'fetch_url':
                self.config.fetch_url = urlparse(v)
            elif k == 'local_url':
                self.config.local_url = urlparse(v)
            elif k == 'direction':
                self.config.direction = v
            elif k == 'rule_file':
                self.config.rule_file = v
            elif k == 'log_level':
                self.config.log_level = v.upper()
            else:
                raise ValueError(f'invalid args {args}')
            self.config.save()
        except Exception as e:
            print(f'set failed: {e}')

    def complete_set(self, text: str, line: str, begidx: int,
                     endidx: int) -> List[str]:
        """Set command completion."""
        return [key for key in self.keys if key.startswith(text)]

    def do_list(self, args: str):
        """Do list."""
        self.config.print()

    def do_run(self, args: str):
        """Do run."""
        try:
            self.config.logging_config()
            self.config.run([int(arg) for arg in args.split()])
        except Exception as e:
            print(f'run failed: {e}')

    def do_delete(self, args: str):
        """Do delete."""
        try:
            self.config.delete([int(arg) for arg in args.split()])
            self.config.print()
            self.config.save()
        except Exception as e:
            print(f'delete failed: {e}')

    def do_ping(self, args: str):
        """Do ping."""
        try:
            self.config.ping([int(arg) for arg in args.split()])
            self.config.print()
            self.config.save()
        except Exception as e:
            print(f'ping failed: {e}')

    def do_fetch(self, args: str):
        """Do fetch."""
        proxy = args if args else None
        try:
            self.config.fetch(proxy)
            self.config.print()
            self.config.save()
        except Exception as e:
            print(f'fetch failed: {e}')


def main():
    """Main entry to run VmessCli.

    Run command if provided, or else run command loop.
    """
    parser = argparse.ArgumentParser(
        prog='vmessc',
        description='vmess proxy protocol client',
    )
    parser.add_argument('-c', '--config-file', default=CONFIG_FILE)
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()

    config_file = args.config_file
    command = args.command

    cli = VmessCli(config_file=config_file)
    try:
        if command:
            cli.onecmd(' '.join(command))
        else:
            cli.cmdloop()
    except KeyboardInterrupt:
        print('keyboard quit')


if __name__ == '__main__':
    main()
