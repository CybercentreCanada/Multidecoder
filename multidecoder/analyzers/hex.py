from __future__ import annotations

import re

from binascii import unhexlify

from multidecoder.hit import Hit
from multidecoder.registry import analyzer

HEX_RE = rb'((?:[a-f0-9]{2}){10,}|(?:[A-F0-9]{2}){10,})'

@analyzer('data')
def find_hex(data: bytes) -> list[Hit]:
    return [
        Hit(unhexlify(match.group(0)), *match.span(0), 'decoded.hexadecimal') for match in re.finditer(HEX_RE, data)
    ]