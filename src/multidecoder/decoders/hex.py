from __future__ import annotations

from binascii import unhexlify

import regex as re

from multidecoder.node import Node
from multidecoder.registry import decoder

HEX_RE = rb"((?:[a-f0-9]{2}){10,}|(?:[A-F0-9]{2}){10,})"


@decoder
def find_hex(data: bytes) -> list[Node]:
    return [
        Node("", unhexlify(match.group(0)), "decoded.hexadecimal", *match.span(0))
        for match in re.finditer(HEX_RE, data)
    ]
