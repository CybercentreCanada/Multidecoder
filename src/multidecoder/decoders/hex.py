from __future__ import annotations

from binascii import Error as binascii_error
from binascii import unhexlify

import regex as re
from multidecoder.node import Node
from multidecoder.registry import decoder

HEX_RE = rb"((?:[a-f0-9]{2}){10,}|(?:[A-F0-9]{2}){10,})"
FROMHEXSTRING_RE = rb"(?i)(\[System.Convert\]::)?FromHexString\('" + HEX_RE + rb"'\)"


@decoder
def find_hex(data: bytes) -> list[Node]:
    """
    Find all hexadecimal encoded sections in some data.

    Args:
        data: The data to search.
    Returns:
        A list of decoded hexadecimal sections and the location indexes of the section
        in the original data.
    """
    return [
        Node("", unhexlify(match.group(0)), "decoded.hexadecimal", *match.span(0))
        for match in re.finditer(HEX_RE, data)
    ]


@decoder
def find_FromHexString(data: bytes) -> list[Node]:
    """
    Find the powershell function FromHexString and decode its argument

    Inspired by https://github.com/CYB3RMX/Qu1cksc0pe/blob/1a349826b248e578b0a2ec8b152eeeddf059c388/Modules/powershell_analyzer.py#L57
    """
    out: list[Node] = []
    xorkey = re.search(rb"(?i)-b?xor\s*(\d{1,3})", data)
    for match in re.finditer(FROMHEXSTRING_RE, data):
        try:
            hex = unhexlify(match.group(2))
            hex_node = Node("powershell.bytes", hex, "encoding.hexidecimal", *match.span())
            if xorkey:
                key = int(xorkey.group(1))
                hex = bytes(b ^ key for b in hex)
                hex_node.children.append(
                    Node(
                        "powershell.bytes",
                        hex,
                        "cipher.xor" + str(key),
                        end=len(hex),
                        parent=hex_node,
                    )
                )
            out.append(hex_node)
        except binascii_error:
            continue
    return out
