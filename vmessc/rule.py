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

  ruleMatcher = RuleMatcher(direction='direct', rule_file='rule.txt')
  rule = ruleMatcher.match('www.baidu.com')
  if rule == Rule.Block:
    print('block')
  elif rule == Rule.Direct:
    print('direct')
  elif rule == Rule.Forward:
    print('forward')
"""

import functools

from typing import Optional, Dict
from typing_extensions import Self
from enum import Enum


class Rule(Enum):
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
            return cls.Block
        elif s == 'direct':
            return cls.Direct
        elif s == 'forward':
            return cls.Forward
        raise ValueError(f'invalid rule string: {s}')


class RuleMatcher:
    direction: Rule  # default rule
    rules: Optional[Dict[str, Rule]]  # static rules table

    def __init__(self,
                 direction: str = 'direct',
                 rule_file: Optional[str] = None):
        """
        Args:
            direction: String of default rule.
            rule_file: Rule set file path, leave None means don't use rule.
        """
        self.direction = Rule.from_string(direction)
        self.rules = self.load(rule_file) if rule_file else None

    @classmethod
    def load(cls, rule_file: str) -> Dict[str, Rule]:
        """Load rule from rule set file.

        Args:
            rule_file: Rule set file path.

        Returns:
            Dict from domain to rule.
        """
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
