from __future__ import annotations

from binascii import unhexlify

import regex as re

from multidecoder.hit import Hit
from multidecoder.registry import analyzer

HEX_RE = rb"((?:[a-f0-9]{2}){10,}|(?:[A-F0-9]{2}){10,})"


@analyzer("")
def find_hex(data: bytes) -> list[Hit]:
    return [
        Hit(unhexlify(match.group(0)), ["decoded.hexadecimal"], *match.span(0))
        for match in re.finditer(HEX_RE, data)
    ]
