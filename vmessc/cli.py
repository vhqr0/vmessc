import logging

from cmd import Cmd

from typing import List

from .config import VmessConfig


class VmessCli(Cmd):
    config: VmessConfig
    keys: List[str]

    keys = ['url', 'direction', 'rule_file', 'log_level', 'local_addr']

    intro = 'Welcome to vmess cli. Type help or ? to list commands.\n'
    prompt = 'vmess cli $ '

    def __init__(self, config_file: str = 'config.json'):
        super().__init__()
        self.config = VmessConfig(config_file=config_file)
        self.config.load()

    def do_EOF(self, args: str):
        raise KeyboardInterrupt

    def do_set(self, args: str):
        try:
            tokens = args.split()
            if len(tokens) != 2:
                raise ValueError(f'invalid args {args}')
            k, v = tokens
            if k == 'url':
                self.config.url = v
            elif k == 'direction':
                self.config.direction = v
            elif k == 'rule_file':
                self.config.rule_file = v
            elif k == 'log_level':
                self.config.log_level = v
            elif k == 'local_addr':
                self.config.local_addr = v
            else:
                raise ValueError(f'invalid args {args}')
            self.config.save()
        except Exception as e:
            print(f'set failed: {e}')

    def complete_set(self, text: str, line: str, begidx: int,
                     endidx: int) -> List[str]:
        return [key for key in self.keys if key.startswith(text)]

    def do_list(self, args: str):
        if args:
            print(f'invalid args: {args}')
        self.config.print()

    def do_run(self, args: str):
        try:
            logging.basicConfig(level=self.config.log_level)
            self.config.run([int(arg) for arg in args.split()])
        except Exception as e:
            print('run failed: %s', e)

    def do_ping(self, args: str):
        try:
            self.config.ping([int(arg) for arg in args.split()])
            self.config.print()
            self.config.save()
        except Exception as e:
            print('ping failed: %s', e)

    def do_delete(self, args: str):
        try:
            self.config.delete([int(arg) for arg in args.split()])
            self.config.print()
            self.config.save()
        except Exception as e:
            print('delete failed: %s', e)

    def do_fetch(self, args: str):
        proxy = args if args else None
        try:
            self.config.fetch(proxy)
            self.config.print()
            self.config.save()
        except Exception as e:
            print('fetch failed: %s', e)
