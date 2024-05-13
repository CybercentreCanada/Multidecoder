"""
Character encodings
"""

from __future__ import annotations

import regex as re

from multidecoder.node import Node
from multidecoder.registry import decoder

UTF16_RE = (
    rb"(?s)(?:[^\x00-\x08\x0e-\x1f\x7f-\x9f]\x00){7,}"
    rb"(?:\x00\x00(?:\x00\x00)?(?:[^\x00-\x08\x0e-\x1f\x7f-\x9f]\x00){7,})*"
)


@decoder
def find_utf16(data: bytes) -> list[Node]:
    """Find utf-16 and convert it to utf-8"""
    return [
        Node(
            "",
            match.group().decode("utf-16").encode("utf-8"),
            "codec.uft-16",
            *match.span(),
        )
        for match in re.finditer(UTF16_RE, data)
    ]
