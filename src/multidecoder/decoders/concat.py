from __future__ import annotations

import regex as re

from multidecoder.node import Node
from multidecoder.registry import decoder

DOUBLE_QUOTE_ESCAPES = rb'\\""?|""|`"'
# Single or double quoted strings with various possible escapes for ' or "
DOUBLE_QUOTE_STRING_RE = rb'"(?:[^"`\\]*(?:""|`.|\\[^"]|\\""?))*[^"`\\]*"'
SINGLE_QUOTE_STRING_RE = rb"'(?:[^']*'')*[^']*'"
STRING_RE = rb"(?:" + DOUBLE_QUOTE_STRING_RE + rb"|" + SINGLE_QUOTE_STRING_RE + rb")"
# _ is VB line continuation character
CONCAT_SPACER_RE = rb"[\s_]*(?:&|\+|&amp;)[\s_]*"
CONCAT_RE = rb"(?:" + STRING_RE + CONCAT_SPACER_RE + rb")+" + STRING_RE


@decoder
def find_concat(data: bytes) -> list[Node]:
    """Find and decode string concatenation"""
    return [
        Node(
            "string",
            re.sub(rb"['\"]" + CONCAT_SPACER_RE + rb"['\"]", b"", match.group())[1:-1],
            "concatenation",
            match.start(),
            match.end(),
        )
        for match in re.finditer(CONCAT_RE, data)
    ]
