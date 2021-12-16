from __future__ import annotations

import re

from multidecoder.hit import Hit

from multidecoder.registry import analyzer

CONCAT_RE = rb'"([^"]+)"\s*(?:&|\+)\s*"([^"]+)"'

@analyzer('concatenation')
def find_concat(data: bytes) -> list[Hit]:
    return [
        Hit(b'"' + match.group(1) + match.group(2) + b'"', *match.span(0)) for match in re.finditer(CONCAT_RE, data)
    ]