import argparse

from .cli import VmessCli


def main():
    parser = argparse.ArgumentParser(
        prog='vmessc',
        description='vmess proxy protocol client',
    )
    parser.add_argument('-c', '--config-file', default='config.json')
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
