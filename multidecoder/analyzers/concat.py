from __future__ import annotations

import re

from multidecoder.hit import Hit

from multidecoder.registry import analyzer

# Single or double quoted strings with various possible escapes for ' or "
STRING_RE = rb'(?:"(?:\\""|""|\\"|`"|[^"])*"|\'(?:[^\']|\'\')*\')'
CONCAT_RE = rb'(?:' + STRING_RE + rb'\s*(?:&|\+)\s*)+' + STRING_RE

@analyzer('string')
def find_concat(data: bytes) -> list[Hit]:
    return [
        Hit(
            b''.join(string[1:-1] for string in re.findall(STRING_RE, match.group())),
            match.start(),
            match.end(),
            'concatenation'
        ) for match in re.finditer(CONCAT_RE, data)
    ]