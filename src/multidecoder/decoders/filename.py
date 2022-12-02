from __future__ import annotations

from multidecoder.hit import Node, regex_hits
from multidecoder.registry import decoder

EXECUTABLE_RE = rb"(?i)\b\w+[.]exe\b"
LIBRARY_RE = rb"(?i)\b\w+[.]dll\b"


@decoder
def find_executable_name(data: bytes) -> list[Node]:
    """Find exe files"""
    return regex_hits("executable.filename", EXECUTABLE_RE, data)


@decoder
def find_library(data: bytes) -> list[Node]:
    """Find dll files"""
    return regex_hits("executable.library.filename", LIBRARY_RE, data)
