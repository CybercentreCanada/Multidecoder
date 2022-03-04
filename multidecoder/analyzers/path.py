from __future__ import annotations

from multidecoder.registry import analyzer
from multidecoder.hit import Hit, regex_hits

PATH_RE = rb'[.]?[.]?/(\w{3,}/)+[\w.]{3,}'
WINDOWS_PATH_RE = rb'(?:[A-Z]:\\?|[.]\\|[.][.]\\|\\)(?:\w{3,}\\)+[\w.]{3,}'


@analyzer('path')
def find_path(data: bytes) -> list[Hit]:
    return regex_hits(PATH_RE, data)


@analyzer('path.windows')
def find_windows_path(data: bytes) -> list[Hit]:
    return regex_hits(WINDOWS_PATH_RE, data)
