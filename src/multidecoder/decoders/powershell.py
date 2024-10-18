from __future__ import annotations

import regex as re

from multidecoder.node import Node
from multidecoder.registry import decoder
from multidecoder.xor_helper import apply_xor_key, get_xorkey

POWERSHELL_BYTES_RE = rb"(?i)(?:(?:0x[0-9a-f]{2}|\d{1,3}),\s*){500,}(?:0x[0-9a-f]{2}|\d{1,3})"

POWERSHELL_BYTES_TYPE = "powershell.bytes"


@decoder
def find_powershell_bytes(data: bytes) -> list[Node]:
    out = []
    for match in re.finditer(POWERSHELL_BYTES_RE, data):
        try:
            binary = bytes(
                int(byte.strip().decode(), 16 if byte.startswith(b"0x") else 10) for byte in match.group().split(b",")
            )
        except ValueError:
            continue  # byte not in 0-256
        node = Node(POWERSHELL_BYTES_TYPE, binary, "", *match.span())
        if key := get_xorkey(data):
            apply_xor_key(key, binary, node, POWERSHELL_BYTES_TYPE)
        out.append(node)

    return out
