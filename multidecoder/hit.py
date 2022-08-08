from __future__ import annotations

import regex as re

from typing import Callable, NamedTuple

Hit = NamedTuple('Hit', [('value', bytes), ('obfuscation', list[str]), ('start', int), ('end', int)])


def match_to_hit(match: re.Match[bytes], group: int = 0) -> Hit:
    return Hit(match.group(group), [], *match.span(group))


def regex_hits(regex: bytes, data: bytes, group: int = 0) -> list[Hit]:
    return [match_to_hit(match, group) for match in re.finditer(regex, data)]


def find_and_deobfuscate(regex: bytes,
                         data: bytes,
                         deobfuscation: Callable[[bytes], tuple[bytes, list[str]]],
                         deob_group: int = 0,
                         context_group: int = 0) -> list[Hit]:
    return [
        Hit(*deobfuscation(match.group(deob_group)), *match.span(context_group)) for match in re.finditer(regex, data)
    ]
