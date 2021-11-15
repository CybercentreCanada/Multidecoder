import re

from typing import NamedTuple

Hit = NamedTuple('Hit', [('value', bytes), ('start', int), ('end', int)])

def match_to_hit(match: re.Match[bytes], group: int = 0) -> Hit:
    return Hit(match.group(group), *match.span(group))