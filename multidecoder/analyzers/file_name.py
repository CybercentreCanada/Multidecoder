from __future__ import annotations

import re

from multidecoder.registry import analyzer
from multidecoder.hit import Hit, match_to_hit

EXECUTABLE_RE = rb'(?i)\\?(?:[\w ]+\\)*\w+[.]exe'

@analyzer('filename.executable')
def find_executable_name(data: bytes) -> list[Hit]:
    return [
        match_to_hit(match) for match in re.finditer(EXECUTABLE_RE, data)
    ]
