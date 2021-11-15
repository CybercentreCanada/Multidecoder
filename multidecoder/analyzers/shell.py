
import re

from typing import List

from multidecoder.hit import Hit, match_to_hit
from multidecoder.registry import analyzer

CMD_RE = rb'(?i)"(\s*cmd[^"]+)"'
POWERSHELL_RE = rb'(?i)"(\s*powershell[^"]+)"'
SH_RE = rb'"(\s*(?:sh|bash|zsh|csh)[^"]+)"'

@analyzer('shell.cmd')
def find_cmd_strings(data: bytes) -> List[Hit]:
    return [match_to_hit(match, 1) for match in re.finditer(CMD_RE, data)]

@analyzer('shell.powershell')
def find_powershell_strings(data: bytes) -> List[Hit]:
    return [match_to_hit(match, 1) for match in re.finditer(POWERSHELL_RE, data)]