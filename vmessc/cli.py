"""Vmess clinet command line interface.

Call VmessConfig methods in command line with completion.

Usage example:

  cli = VmessCli(config_file='config.json')
  cli.cmdloop()
"""

from urllib.parse import urlparse
import logging

from typing import List
from cmd import Cmd

from .config import VmessConfig


class VmessCli(Cmd):
    """Vmess client command line interface.

    Attributes:
        config: Client config manager.
        keys: Set command completion keywords.
    """
    config: VmessConfig
    keys: List[str]

    keys = ['fetch_url', 'direction', 'rule_file', 'log_level', 'local_url']

    intro = 'Welcome to vmess cli. Type help or ? to list commands.\n'
    prompt = 'vmess cli $ '

    def __init__(self, config_file: str = 'config.json'):
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
            elif k == 'direction':
                self.config.direction = v
            elif k == 'rule_file':
                self.config.rule_file = v
            elif k == 'log_level':
                self.config.log_level = v
            elif k == 'local_url':
                self.config.local_url = urlparse(v)
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
            logging.basicConfig(level=self.config.log_level)
            self.config.run([int(arg) for arg in args.split()])
        except Exception as e:
            print('run failed: %s', e)

    def do_delete(self, args: str):
        """Do delete."""
        try:
            self.config.delete([int(arg) for arg in args.split()])
            self.config.print()
            self.config.save()
        except Exception as e:
            print('delete failed: %s', e)

    def do_ping(self, args: str):
        """Do ping."""
        try:
            self.config.ping([int(arg) for arg in args.split()])
            self.config.print()
            self.config.save()
        except Exception as e:
            print('ping failed: %s', e)

    def do_fetch(self, args: str):
        """Do fetch."""
        proxy = args if args else None
        try:
            self.config.fetch(proxy)
            self.config.print()
            self.config.save()
        except Exception as e:
            print('fetch failed: %s', e)
