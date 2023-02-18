"""Rule recursive matcher implementation.

There are three type of rules:
  Block: Drop request.
  Direct: Make connection directly.
  Forward: Make connection via a vmess node.

Rule set example:

  direct\tbaidu.com
  forward\tgoogle.com

While `baidu.com`, `www.baidu.com` will match rule Direct, and
`google.com`, `www.google.com` will match rule Forward.

Usage example:

  rule_matcher = RuleMatcher(direction='direct', rule_file='rule.txt')
  rule = rule_matcher.match('www.baidu.com')
  if rule == Rule.Block:
    print('block')
  elif rule == Rule.Direct:
    print('direct')
  elif rule == Rule.Forward:
    print('forward')
"""

import os.path
import functools
import logging
import argparse

from typing import Optional, Dict
from typing_extensions import Self
from enum import Enum

from .defaults import (
    RULE_FILE,
    DIRECTION,
)


class Rule(Enum):
    """Represent a proxy rule: one of Block, Direct or Forward.

    Convert from:
      int Rule.__init__ (1, 2, 3)
      str Rule.from_string ('block', 'direct', 'forward')

    Convert to:
      str Rule.__str__
    """
    Block = 1
    Direct = 2
    Forward = 3

    def __str__(self) -> str:
        if self == self.Block:
            return 'block'
        elif self == self.Direct:
            return 'direct'
        elif self == self.Forward:
            return 'forward'
        return '<invalid rule>'

    @classmethod
    def from_string(cls, s: str) -> Self:
        """Convert string to rule.

        Args:
            s: One of 'block', 'direct' or 'forward'.

        Returns:
            One of Rule.Block, Rule.Direct or Rule.Forward.

        Raises:
            Raise ValueError when s not in the three.
        """
        s = s.lower()
        if s == 'block':
            return cls(cls.Block)
        elif s == 'direct':
            return cls(cls.Direct)
        elif s == 'forward':
            return cls(cls.Forward)
        raise ValueError(f'invalid rule string: {s}')


class RuleMatcher:
    """Rule matcher.

    Rule match domain or domain's super domain by calling
    matcher.match(domain).

    Attributes:
        direction: Default rule when missing.
        rules: Dict from domain to rule, None means don't use rule.
    """
    direction: Rule
    rules: Optional[Dict[str, Rule]]

    def __init__(self, direction: str = DIRECTION, rule_file: str = RULE_FILE):
        """
        Args:
            direction: String of default rule.
            rule_file: Rule set file path, leave empty or non-exists path
              means don't use rule.
        """
        self.direction = Rule.from_string(direction)
        self.rules = self.load(rule_file)

    @classmethod
    def load(cls, rule_file: str) -> Optional[Dict[str, Rule]]:
        """Load rule from rule set file.

        Args:
            rule_file: Rule set file path.

        Returns:
            A dict map from domain to rule.
        """
        rule_file = rule_file.strip()
        if len(rule_file) == 0:
            return None
        if not os.path.exists(rule_file):
            logging.warning('rule file is not exists: %s', rule_file)
            return None

        rules = dict()

        with open(rule_file) as rf:
            for line in rf:
                line = line.strip()
                if len(line) == 0 or line[0] == '#':  # void or comment line
                    continue
                tokens = line.split()
                if len(tokens) != 2:
                    raise ValueError(f'invalid rule: {line}')
                rule = Rule.from_string(tokens[0])
                domain = tokens[1]
                if domain in rules:
                    # previous rule has higher priority
                    continue
                rules[domain] = rule

        return rules

    @functools.cache
    def match(self, domain: str) -> Rule:
        """Match rule of a domain.

        Args:
            domain: domain to match.

        Returns:
            Rule match domain or one of domain's super domain, or default rule.
        """
        if self.rules is None:
            return self.direction
        rule = self.rules.get(domain)
        if rule is not None:
            return rule
        # recursive match super domain
        pos = domain.find('.')
        if pos > 0:
            return self.match(domain[pos + 1:])
        return self.direction


def main():
    """Main entry to match rules of domains."""
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--direction', default=DIRECTION)
    parser.add_argument('-r', '--rule-file', default=RULE_FILE)
    parser.add_argument('domains', nargs=argparse.REMAINDER)
    args = parser.parse_args()

    direction = args.direction
    rule_file = args.rule_file
    domains = args.domains

    matcher = RuleMatcher(direction=direction, rule_file=rule_file)

    for domain in domains:
        rule = matcher.match(domain)
        print(f'{rule}\t{domain}')


if __name__ == '__main__':
    main()
