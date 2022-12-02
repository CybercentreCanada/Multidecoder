from __future__ import annotations

import regex as re

from multidecoder.node import Node
from multidecoder.registry import decoder

CHR_RE = rb"(?i)chr[bw]?\((\d+)\)"


@decoder
def find_chr(data: bytes) -> list[Node]:
    """Find and decode calls to the chr function"""
    return [
        Node("string", chr(int(match.group(1))).encode(), "function.chr", *match.span())
        for match in re.finditer(CHR_RE, data)
    ]
