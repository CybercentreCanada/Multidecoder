from __future__ import annotations

import regex as re

from multidecoder.node import Node
from multidecoder.registry import decoder

CHR_RE = rb"(?i)chr[bw]?\((0*\d{1,5})\)"


@decoder
def find_chr(data: bytes) -> list[Node]:
    """Find and decode calls to the chr function"""
    out = []
    for match in re.finditer(CHR_RE, data):
        try:
            character = chr(int(match.group(1))).encode()
        except (ValueError, UnicodeEncodeError):
            continue
        out.append(Node("string", character, "function.chr", *match.span()))
    return out
