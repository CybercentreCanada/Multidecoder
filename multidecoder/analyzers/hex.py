from __future__ import annotations

import re

from binascii import unhexlify

from multidecoder.hit import Hit
from multidecoder.registry import analyzer

HEX_RE = rb'((?:[a-z0-9]{2}){10,}|(?:[A-Z0-9]{2}){10,})'

@analyzer('encoding.hexadecimal')
def find_hex(data: bytes) -> list[Hit]:
    return [
        Hit(unhexlify(match.group(0)), *match.span(0)) for match in re.finditer(HEX_RE, data)
    ]