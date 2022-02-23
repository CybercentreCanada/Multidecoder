from __future__ import annotations

import re

from multidecoder.hit import Hit

from multidecoder.registry import analyzer

REPLACE_RE = rb'replace\("([^"]*)",\s*"([^"]*)",\s*"([^"]*)"\)'
@analyzer('string')
def find_replace(data: bytes) -> list[Hit]:
    return [
        Hit(match.group(1).replace(match.group(2), match.group(3)), *match.span(), 'vba.replace')
        for match in re.finditer(REPLACE_RE, data)
    ]
