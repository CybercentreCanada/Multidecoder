from __future__ import annotations

from urllib.parse import unquote_to_bytes
import regex as re

from multidecoder.hit import Hit
from multidecoder.registry import analyzer

UNESCAPE_RE = rb"unescape\('([^']*)'\)"


@analyzer('string')
def find_unescape(data: bytes) -> list[Hit]:
    return [
        Hit(unquote_to_bytes(match.group(1)), 'function.unescape', *match.span())
        for match in re.finditer(UNESCAPE_RE, data)
    ]
