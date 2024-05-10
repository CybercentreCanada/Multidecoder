from __future__ import annotations

from multidecoder.decoders.concat import STRING_RE
from multidecoder.hit import find_and_deobfuscate
from multidecoder.node import Node
from multidecoder.registry import decoder

REVERSE_RE = rb"(?i)reversed?\(\s*(" + STRING_RE + rb")\s*\)"


@decoder
def find_reverse(data: bytes) -> list[Node]:
    return find_and_deobfuscate("string", REVERSE_RE, data, lambda s: (s[-2:0:-1], "reverse"), 1)
