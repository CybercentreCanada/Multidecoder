from __future__ import annotations

from typing import TYPE_CHECKING

from multidecoder.hit import regex_hits
from multidecoder.registry import decoder

if TYPE_CHECKING:
    from multidecoder.node import Node

EXECUTABLE_TYPE = "executable.filename"
LIBRARY_TYPE = "executable.library.filename"

EXT_MAP = {b".dll": LIBRARY_TYPE, b".exe": EXECUTABLE_TYPE}

EXECUTABLE_RE = rb"(?i)\b\w+[.]exe\b"
LIBRARY_RE = rb"(?i)\b\w+[.]dll\b"


@decoder
def find_executable_name(data: bytes) -> list[Node]:
    """Find exe files"""
    return regex_hits(EXECUTABLE_TYPE, EXECUTABLE_RE, data)


@decoder
def find_library(data: bytes) -> list[Node]:
    """Find dll files"""
    return regex_hits(EXECUTABLE_TYPE, LIBRARY_RE, data)
