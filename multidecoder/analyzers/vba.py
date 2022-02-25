from __future__ import annotations

import re

from multidecoder.hit import Hit
from multidecoder.registry import analyzer

VBA_FUNC_RE = rb'(?i)createobject\('

@analyzer('vba.function')
def find_vba_call(data: bytes) -> list[Hit]:
    out = []

    for match in re.finditer(VBA_FUNC_RE, data):
        balance = 1
        index = match.end()
        while index < len(data) and balance:
            if data[index] == ord(')'):
                balance -= 1
            elif data[index] == ord('('):
                balance += 1
            index += 1
        if balance == 0:
            out.append(Hit(data[match.start():index], match.start(), index, ''))
    return out