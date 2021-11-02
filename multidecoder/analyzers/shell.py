
import re

from typing import List

from multidecoder.hit import Hit, match_to_hit
from multidecoder.registry import analyzer

SHELL_RE = rb'(?i)"\s*(?:powershell|cmd|shell)[^"]+"'

@analyzer('shell')
def find_shell_strings(data: bytes) -> List[Hit]:
    return [match_to_hit(match) for match in re.finditer(SHELL_RE, data)]