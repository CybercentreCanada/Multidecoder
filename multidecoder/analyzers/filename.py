from __future__ import annotations

from multidecoder.registry import analyzer
from multidecoder.hit import Hit, regex_hits

EXECUTABLE_RE = rb'(?i)\b\w+[.]exe\b'
LIBRARY_RE = rb'(?i)\b\w+[.]dll\b'


@analyzer('executable.filename')
def find_executable_name(data: bytes) -> list[Hit]:
    return regex_hits(EXECUTABLE_RE, data)


@analyzer('executable.library.filename')
def find_library(data: bytes) -> list[Hit]:
    return regex_hits(LIBRARY_RE, data)
