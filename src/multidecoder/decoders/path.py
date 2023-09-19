from __future__ import annotations

from multidecoder.hit import regex_hits
from multidecoder.node import Node
from multidecoder.registry import decoder

PATH_RE = rb"[.]?[.]?/(\w{3,}/)+[\w.]{3,}"
WINDOWS_PATH_RE = rb"(?:[A-Z]:\\?|[.]\\|[.][.]\\|\\)(?:\w{3,}\\)+[\w.]{3,}"


@decoder
def find_path(data: bytes) -> list[Node]:
    return regex_hits("path", PATH_RE, data)


@decoder
def find_windows_path(data: bytes) -> list[Node]:
    return regex_hits("windows.path", WINDOWS_PATH_RE, data)
