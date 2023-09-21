from __future__ import annotations

from typing import Callable

import regex as re

from multidecoder.node import Node


def match_to_hit(label: str, match: re.Match[bytes], group: int = 0) -> Node:
    return Node(label, match.group(group), "", *match.span(group))


def regex_hits(label: str, regex: bytes, data: bytes, group: int = 0) -> list[Node]:
    return [match_to_hit(label, match, group) for match in re.finditer(regex, data)]


def find_and_deobfuscate(
    label: str,
    regex: bytes,
    data: bytes,
    deobfuscation: Callable[[bytes], tuple[bytes, str]],
    deob_group: int = 0,
    context_group: int = 0,
) -> list[Node]:
    return [
        Node(label, *deobfuscation(match.group(deob_group)), *match.span(context_group))
        for match in re.finditer(regex, data)
    ]
