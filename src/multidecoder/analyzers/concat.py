from __future__ import annotations

import regex as re

from multidecoder.node import Node
from multidecoder.registry import decoder

DOUBLE_QUOTE_ESCAPES = rb'\\""|""|\\"|`"'
# Single or double quoted strings with various possible escapes for ' or "
DOUBLE_QUOTE_STRING_RE = rb'"(?:' + DOUBLE_QUOTE_ESCAPES + rb'|[^"])*"'
SINGLE_QUOTE_STRING_RE = rb"'(?:[^']|'')*'"
STRING_RE = rb"(?:" + DOUBLE_QUOTE_STRING_RE + rb"|" + SINGLE_QUOTE_STRING_RE + rb")"
# _ is VB line continuation character
CONCAT_RE = rb"(?:" + STRING_RE + rb"[\s_]*(?:&|\+|&amp;)[\s_]*)+" + STRING_RE


@decoder
def find_concat(data: bytes) -> list[Node]:
    """Find and decode string concatenation"""
    return [
        Node(
            "string",
            b"".join(string[1:-1] for string in re.findall(STRING_RE, match.group())),
            "concatenation",
            match.start(),
            match.end(),
        )
        for match in re.finditer(CONCAT_RE, data)
    ]
