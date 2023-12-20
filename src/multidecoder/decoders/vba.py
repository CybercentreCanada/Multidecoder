from __future__ import annotations

import regex as re

from multidecoder.decoders.concat import STRING_RE
from multidecoder.hit import find_and_deobfuscate
from multidecoder.node import Node
from multidecoder.registry import decoder

CREATE_OBJECT_RE = rb"(?i)createobject\("
STRREVERSE_RE = rb"(?i)StrReverse\(\s*(" + STRING_RE + rb")\s*\)"

OPEN_TO_CLOSE_MAP = {
    ord("("): ord(")"),
    ord("{"): ord("}"),
    ord("["): ord("]"),
    ord("<"): ord(">"),
}


def get_closing_brace(data: bytes, start_index: int, brace_ord: int = ord("(")) -> int:
    if brace_ord not in OPEN_TO_CLOSE_MAP:
        raise ValueError("Unsupported brace type")
    balance = 1
    index = start_index
    while index < len(data) and balance:
        if data[index] == OPEN_TO_CLOSE_MAP[brace_ord]:
            balance -= 1
        elif data[index] == brace_ord:
            balance += 1
        index += 1
    if balance == 0:
        return index
    return -1


@decoder
def find_createobject(data: bytes) -> list[Node]:
    out = []
    for match in re.finditer(CREATE_OBJECT_RE, data):
        index = get_closing_brace(data, match.end())
        if index > 0:
            out.append(
                Node(
                    "vba.function.createobject",
                    data[match.start() : index],
                    "",
                    match.start(),
                    index,
                )
            )
    return out


@decoder
def find_strreverse(data: bytes) -> list[Node]:
    return find_and_deobfuscate("vba.string", STRREVERSE_RE, data, lambda s: (s[-2:0:-1], "vba.reverse"), 1)
