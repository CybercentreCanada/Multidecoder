from __future__ import annotations

import regex as re

from multidecoder.hit import Hit

from multidecoder.registry import analyzer

DOUBLE_QUOTE_ESCAPES = rb'\\""|""|\\"|`"'
# Single or double quoted strings with various possible escapes for ' or "
STRING_RE = rb'(?:"(?:' + DOUBLE_QUOTE_ESCAPES + rb'|[^"])*"|\'(?:[^\']|\'\')*\')'
CONCAT_RE = rb'(?:' + STRING_RE + rb'\s*(?:&|\+|&amp;)\s*)+' + STRING_RE


@analyzer('string')
def find_concat(data: bytes) -> list[Hit]:
    return [
        Hit(
            b''.join(string[1:-1] for string in re.findall(STRING_RE, match.group())),
            'concatenation',
            match.start(),
            match.end(),
        ) for match in re.finditer(CONCAT_RE, data)
    ]
