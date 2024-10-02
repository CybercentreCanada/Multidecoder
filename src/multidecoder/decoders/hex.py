from __future__ import annotations

from binascii import Error as binascii_error
from binascii import unhexlify

import regex as re

from multidecoder.node import Node
from multidecoder.registry import decoder
from multidecoder.xor_helper import apply_xor_key, get_xorkey

HEX_RE = rb"((?:[a-f0-9]{2}){10,}|(?:[A-F0-9]{2}){10,})"
HEX_SPACE_RE = rb"(?i)(?:[a-f0-9]{2}\s+){9,}[a-f0-9]{2}"
HEX_COMMA_RE = rb"(?i)(?:[a-f0-9]{2}\s*,\s*){9,}[a-f0-9]{2}"
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


def find_hex_space(data: bytes) -> list[Node]:
    """Find sequences of hexadecimal octets separated by whitespace."""
    return [
        Node("", unhexlify(re.sub(rb"\s+", b"", match.group(0))), "decoded.hexadecimal", *match.span(0))
        for match in re.finditer(HEX_SPACE_RE, data)
    ]


def find_hex_comma(data: bytes) -> list[Node]:
    """Find sequences of hexadecimal octets separated by commas.

    examples:
    - a1,b2,c3,d4
    - a1, b2, c3, d4
    - a1 , b2 , c3 , d4
    Handles any combination of a single comma and optional whitespace on either side
    """
    return [
        Node("", unhexlify(re.sub(rb"[\s,]+", b"", match.group(0))), "decoded.hexadecimal", *match.span(0))
        for match in re.finditer(HEX_COMMA_RE, data)
    ]


@decoder
def find_FromHexString(data: bytes) -> list[Node]:
    """
    Find the powershell function FromHexString and decode its argument

    Inspired by https://github.com/CYB3RMX/Qu1cksc0pe/blob/1a349826b248e578b0a2ec8b152eeeddf059c388/Modules/powershell_analyzer.py#L57
    """
    out: list[Node] = []
    xorkey = get_xorkey(data)
    for match in re.finditer(FROMHEXSTRING_RE, data):
        try:
            unhex = unhexlify(match.group(2))
            hex_node = Node("powershell.bytes", unhex, "encoding.hexidecimal", *match.span())
            if xorkey:
                hex_node = apply_xor_key(xorkey, unhex, hex_node, "powershell.bytes")
            out.append(hex_node)
        except binascii_error:
            continue
    return out
