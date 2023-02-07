#!/usr/bin/env python3
"""
Merge https://github.com/v2fly/domain-list-community to one single file.
The four type: domain, full, keyword and regexp, only support domain and full.
Multi-tags syntax is not supported. (So far it doesn't seem to be used.)
"""

import re
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('-d', '--datapath', default='domain-list-community/data')
args = parser.parse_args()

datapath = args.datapath

tag2rule = {
    'ads': 'block',
    'cn': 'direct',
    '!cn': 'forward',
}

line_re = re.compile(r'^((\w+):)?([^\s\t#]+)( @([^\s\t#]+))?')


def load_rule(rule_file: str, default_tag: str):
    for line in open(f'{datapath}/{rule_file}'):
        res = line_re.match(line.strip())
        if res is None:
            continue
        command = res[2] or 'domain'
        target = res[3]
        tag = res[5] or default_tag
        rule = tag2rule[tag]
        if command in ('domain', 'full'):
            print(f'{rule}\t{target}')
        elif command == 'include':
            load_rule(target, default_tag)


load_rule('cn', 'cn')
load_rule('geolocation-!cn', '!cn')
