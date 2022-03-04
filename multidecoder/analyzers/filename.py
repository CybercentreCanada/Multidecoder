from __future__ import annotations

from multidecoder.registry import analyzer
from multidecoder.hit import Hit, regex_hits

EXECUTABLE_RE = rb'(?i)\b\w+[.]exe\b'
LIBRARY_RE = rb'(?i)\b\w+[.]dll\b'


@analyzer('filename.executable')
def find_executable_name(data: bytes) -> list[Hit]:
    return regex_hits(EXECUTABLE_RE, data)


@analyzer('filename.library')
def find_library(data: bytes) -> list[Hit]:
    return regex_hits(LIBRARY_RE, data)
