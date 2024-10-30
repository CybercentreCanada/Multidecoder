from __future__ import annotations

import regex as re

from multidecoder.node import Node
from multidecoder.registry import decoder
from multidecoder.xor_helper import apply_xor_key, get_xorkey
from multidecoder.xortool import xortool

POWERSHELL_BYTES_RE = rb"(?i)(?:(?:0x[0-9a-f]{2}|\d{1,3}),\s*){500,}(?:0x[0-9a-f]{2}|\d{1,3})"

POWERSHELL_BYTES_TYPE = "powershell.bytes"


@decoder
def find_powershell_bytes(data: bytes) -> list[Node]:
    def decode_byte(byte: bytes) -> int:
        stripped = byte.strip()
        return int(stripped.decode(), 16 if stripped.startswith(b"0x") else 10)

    out = []
    for match in re.finditer(POWERSHELL_BYTES_RE, data):
        try:
            binary = bytes(decode_byte(byte) for byte in match.group().split(b","))
        except ValueError:
            continue  # byte not in 0-256
        node = Node(POWERSHELL_BYTES_TYPE, binary, "", *match.span())
        if key := get_xorkey(data):
            apply_xor_key(key, binary, node, POWERSHELL_BYTES_TYPE)
        elif b"-bxor" in data:
            plaintexts = xortool(binary, [0])
            if plaintexts:
                node.children.append(
                    Node(POWERSHELL_BYTES_TYPE, plaintexts[0], "cipher.multibyte_xor", 0, len(binary), parent=node)
                )
        out.append(node)

    return out
