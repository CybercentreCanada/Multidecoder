from __future__ import annotations

from urllib.parse import unquote_to_bytes

import regex as re

from multidecoder.node import Node
from multidecoder.registry import decoder

UNESCAPE_RE = rb"unescape\('([^']*)'\)"


@decoder
def find_unescape(data: bytes) -> list[Node]:
    return [
        Node(
            "string",
            unquote_to_bytes(match.group(1)),
            "function.unescape",
            *match.span(),
        )
        for match in re.finditer(UNESCAPE_RE, data)
    ]
