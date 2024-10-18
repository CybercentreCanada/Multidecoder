"""
Base 64 encoded text
"""

from __future__ import annotations

import binascii

import regex as re

from multidecoder.decoders.powershell import POWERSHELL_BYTES_TYPE
from multidecoder.node import Node
from multidecoder.registry import decoder
from multidecoder.xor_helper import apply_xor_key, get_xorkey

HTML_ESCAPE_RE = rb"&#(?:x[a-fA-F0-9]{1,4}|\d{1,4});"
BASE64_RE = rb"(?:[A-Za-z0-9+/]{4,}(?:<\x00  \x00)?(?:&#13;|&#xD;)?(?:&#10;|&#xA)?\r?\n?){5,}[A-Za-z0-9+/]{2,}=?=?"
BASE64DECODE_RE = rb"(?i)Base64Decode\(['\"]([a-z0-9/+]+=?=?)['\"]\)"
FROMB64STRING_RE = rb"(?i)(\[System.Convert\]::)?FromBase64String\(['\"]([a-z0-9+/]+=?=?)['\"]\)"
ATOB_RE = rb"atob\(['\"]([A-Za-z0-9+/]+=?=?)['\"]\)"

CAMEL_RE = rb"(?i)[a-z]+"
HEX_RE = rb"(?i)[a-f0-9]+"
MIN_B64_CHARS = 6


def pad_base64(b64: bytes) -> bytes:
    """Force base64 that is the wrong length to be decodable.

    If the length is 1 or 2 characters from a multiple of 4, it is padded with '='s.
    If the length is 3 from a multiple of 4 the last character is removed.
    If the length is a multiple of 4 it is returned unchanged.
    """
    padding = -len(b64) % 4
    if not padding:
        return b64
    if padding == 3:
        return b64[:-1]  # Corrupted end, just keep the valid part
    return b64 + b"=" * padding


@decoder
def find_atob(data: bytes) -> list[Node]:
    """Find the javascript base64 decoding function atob and decode its argument."""
    out: list[Node] = []
    for match in re.finditer(ATOB_RE, data):
        try:
            b64 = binascii.a2b_base64(match.group(1))
            out.append(Node("javascript.string", b64, "encoding.base64", *match.span()))
        except binascii.Error:
            continue
    return out


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

    Supported by https://github.com/CYB3RMX/Qu1cksc0pe/blob/1a349826b248e578b0a2ec8b152eeeddf059c388/Modules/powershell_analyzer.py#L53
    """
    out: list[Node] = []
    xorkey = get_xorkey(data)
    for match in re.finditer(FROMB64STRING_RE, data):
        try:
            b64 = binascii.a2b_base64(match.group(2))
            b64_node = Node(POWERSHELL_BYTES_TYPE, b64, "encoding.base64", *match.span())
            if xorkey:
                b64_node = apply_xor_key(xorkey, b64, b64_node, POWERSHELL_BYTES_TYPE)
            out.append(b64_node)
        except binascii.Error:
            continue
    return out
