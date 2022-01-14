from __future__ import annotations

import re

from multidecoder.registry import analyzer
from multidecoder.hit import Hit, match_to_hit, regex_hits

EXECUTABLE_RE = rb'(?i)\b\w+[.]exe\b'
LIBRARY_RE = rb'(?i)\b\w+[.]dll\b'

PATH_RE = rb'[.]?[.]?/?(\w+/)+[\w.]+'
WINDOWS_PATH_RE = rb'(?:[A-Z]:\\?|[.]\\|[.][.]\\|\\)?(?:\w+\\)+[\w.]+'

@analyzer('path')
def find_path(data: bytes) -> list[Hit]:
    return regex_hits(PATH_RE, data)

@analyzer('path.windows')
def find_windows_path(data: bytes) -> list[Hit]:
    return regex_hits(WINDOWS_PATH_RE, data)

@analyzer('filename.executable')
def find_executable_name(data: bytes) -> list[Hit]:
    return regex_hits(EXECUTABLE_RE, data)

@analyzer('filename.library')
def find_library(data: bytes) -> list[Hit]:
    return regex_hits(LIBRARY_RE, data)