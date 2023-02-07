import functools

from typing import Optional, Dict
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

    # TODO: return type hint
    @classmethod
    def from_string(cls, s: str):
        s = s.lower()
        if s == 'block':
            return cls.Block
        elif s == 'direct':
            return cls.Direct
        elif s == 'forward':
            return cls.Forward
        raise ValueError(f'invalid rule string: {s}')


class RuleMatcher:
    direction: Rule
    rules: Optional[Dict[str, Rule]]

    def __init__(self,
                 direction: str = 'direct',
                 rule_file: Optional[str] = None):
        self.direction = Rule.from_string(direction)
        self.rules = self.load(rule_file) if rule_file else None

    @classmethod
    def load(cls, rule_file: str) -> Dict[str, Rule]:
        rules = dict()
        with open(rule_file) as rf:
            for line in rf:
                line = line.strip()
                if len(line) == 0 or line[0] == '#':  # void or comment line
                    continue
                tokens = line.split()
                if len(tokens) != 2:  # invalid line
                    raise ValueError(f'invalid rule: {line}')
                rule = Rule.from_string(tokens[0])  # may raise ValueError
                domain = tokens[1]
                if domain in rules:
                    # previous rule has higher priority
                    continue
                rules[domain] = rule
        return rules

    @functools.cache
    def match(self, domain: str) -> Rule:
        if self.rules is None:  # no rules
            return self.direction
        rule = self.rules.get(domain)
        if rule is not None:  # match domain
            return rule
        # recursive match super domain
        pos = domain.find('.')
        if pos > 0:
            return self.match(domain[pos + 1:])
        return self.direction  # use default rule
