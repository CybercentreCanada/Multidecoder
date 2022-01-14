from __future__ import annotations

import re

from typing import NamedTuple

Hit = NamedTuple('Hit', [('value', bytes), ('start', int), ('end', int)])

def match_to_hit(match: re.Match[bytes], group: int = 0) -> Hit:
    return Hit(match.group(group), *match.span(group))

def regex_hits(regex: bytes, data: bytes, group: int = 0) -> list[Hit]:
    return [match_to_hit(match, group) for match in re.finditer(regex, data)]