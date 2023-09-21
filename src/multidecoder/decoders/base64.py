"""
Base 64 encoded text
"""

from __future__ import annotations

import binascii

import regex as re

from multidecoder.node import Node
from multidecoder.registry import decoder

HTML_ESCAPE_RE = rb"&#(?:x[a-fA-F0-9]{1,4}|\d{1,4});"
BASE64_RE = rb"(?:[A-Za-z0-9+/]{4,}(?:<\x00  \x00)?(?:&#13;|&#xD;)?(?:&#10;|&#xA)?\r?\n?){5,}[A-Za-z0-9+/]{2,}=?=?"
BASE64DECODE_RE = rb'(?i)Base64Decode\("([a-z0-9/+]+=?=?)"\)'
FROMB64STRING_RE = rb"(?i)(\[System.Convert\]::)?FromBase64String\('([a-z0-9+/]+=?=?)'\)"

CAMEL_RE = rb"(?i)[a-z]+"
HEX_RE = rb"(?i)[a-f0-9]+"
MIN_B64_CHARS = 6


@decoder
def find_base64(data: bytes) -> list[Node]:
    """
    Find all base64 encoded sections in some data.

    Args:
        data: The data to search.
    Returns:
        A list of decoded base64 sections and the location indexes of the section
        in the original data.
    """
    b64_matches = []
    for b64_match in re.finditer(BASE64_RE, data):
        b64_string = (
            re.sub(HTML_ESCAPE_RE, b"", b64_match.group())
            .replace(b"\n", b"")
            .replace(b"\r", b"")
            .replace(b"<\x00  \x00", b"")
        )
        if len(b64_string) % 4 != 0 or len(set(b64_string)) <= MIN_B64_CHARS:
            continue
        if re.fullmatch(HEX_RE, b64_string):
            # Hexadecimal characters are a subset of base64
            # Hashes commonly are hex and have multiple of 4 lengths
            continue
        if re.fullmatch(CAMEL_RE, b64_string):
            # Camel case text can be confused for base64
            # It is common in scripts as names
            continue
        if b64_string.count(b"/") / len(b64_string) > 3 / 32:
            # If there are a lot of / it as more likely a path
            continue
        try:
            b64_result = binascii.a2b_base64(b64_string)
            b64_matches.append(
                Node(
                    "",
                    b64_result,
                    "encoding.base64",
                    b64_match.start(),
                    b64_match.end(),
                )
            )
        except binascii.Error:
            pass
    return b64_matches


@decoder
def find_Base64Decode(data: bytes) -> list[Node]:
    """
    Find the vba function Base64Decode and decode its arguement
    """
    out: list[Node] = []
    for match in re.finditer(BASE64DECODE_RE, data):
        try:
            b64 = binascii.a2b_base64(match.group(1))
            out.append(Node("vba.string", b64, "encoding.base64", *match.span()))
        except binascii.Error:
            continue
    return out


@decoder
def find_FromBase64String(data: bytes) -> list[Node]:
    """
    Find the powershell function FromBase64String and decode its argument
    """
    out: list[Node] = []
    xorkey = re.search(rb"(?i)-b?xor\s*(\d{1,3})", data)
    for match in re.finditer(FROMB64STRING_RE, data):
        try:
            b64 = binascii.a2b_base64(match.group(2))
            b64_node = Node("powershell.bytes", b64, "encoding.base64", *match.span())
            if xorkey:
                key = int(xorkey.group(1))
                b64 = bytes(b ^ key for b in b64)
                b64_node.children.append(
                    Node(
                        "powershell.bytes",
                        b64,
                        "cipher.xor" + str(key),
                        end=len(b64),
                        parent=b64_node,
                    )
                )
            out.append(b64_node)
        except binascii.Error:
            continue
    return out
