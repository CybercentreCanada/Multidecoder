"""
Character encodings
"""
from __future__ import annotations

import regex as re

from multidecoder.hit import Hit
from multidecoder.registry import analyzer

UTF16_RE = rb'(?s)(?:[^\x00-\x08\x0e-\x1f\x7f-\x9f]\x00){14,}'


@analyzer('')
def find_utf16(data: bytes) -> list[Hit]:
    return [
       Hit(match.group().decode('utf-16').encode('utf-8'), 'uft-16', *match.span())
       for match in re.finditer(UTF16_RE, data)
    ]
