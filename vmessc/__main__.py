import argparse

from .cli import VmessCli


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--config-file', default='config.json')
    args = parser.parse_args()

    config_file = args.config_file

    cli = VmessCli(config_file=config_file)
    try:
        cli.cmdloop()
    except KeyboardInterrupt:
        print('keyboard quit')


if __name__ == '__main__':
    main()
