import re

from typing import NamedTuple

Hit = NamedTuple('Hit', [('value', bytes), ('start', int), ('end', int)])

def match_to_hit(match: re.Match) -> Hit:
    return Hit(match.group(), match.start(), match.end())