from __future__ import annotations
from dataclasses import dataclass

import re

from multidecoder.hit import Hit
from multidecoder.registry import analyzer

XML_ESCAPE_RE = rb'(?i)(?:&#(x[a-z0-9]{2}|(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}));){5,}'


def unescape_xml(data: bytes) -> bytes:
    return bytes(
        int(x[1:], base=16) if x.startswith((b'x', b'X')) else int(x)
        for x in data.replace(b'&#', b'').split(b';')[:-1]
    )


@analyzer('obfuscation.escape.xml')
def find_xml_hex(data: bytes) -> list[Hit]:
    return [
        Hit(unescape_xml(match.group()), match.start(), match.end(), 'escape.xml')
        for match in re.finditer(XML_ESCAPE_RE, data)
    ]
