from __future__ import annotations

import regex as re

from multidecoder.hit import Hit
from multidecoder.registry import analyzer

CHR_RE = rb'chr[bw]?\((\d+)\)'


@analyzer('string')
def find_chr(data: bytes) -> list[Hit]:
    return [
        Hit(chr(int(match.group(1))).encode(), 'function.chr', *match.span())
        for match in re.finditer(CHR_RE, data)
    ]
