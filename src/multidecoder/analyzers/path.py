from __future__ import annotations

from multidecoder.hit import Hit, regex_hits
from multidecoder.registry import analyzer

PATH_RE = rb"[.]?[.]?/(\w{3,}/)+[\w.]{3,}"
WINDOWS_PATH_RE = rb"(?:[A-Z]:\\?|[.]\\|[.][.]\\|\\)(?:\w{3,}\\)+[\w.]{3,}"


@analyzer("path")
def find_path(data: bytes) -> list[Hit]:
    return regex_hits(PATH_RE, data)


@analyzer("windows.path")
def find_windows_path(data: bytes) -> list[Hit]:
    return regex_hits(WINDOWS_PATH_RE, data)
