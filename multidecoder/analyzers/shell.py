
import regex as re

from typing import List

from multidecoder.hit import Hit, match_to_hit, find_and_deobfuscate
from multidecoder.registry import analyzer

CMD_RE = rb'(?i)\bcmd[^,)"]+'
POWERSHELL_RE = rb'(?i)"(\s*powershell[^"]+)"'
SH_RE = rb'"(\s*(?:sh|bash|zsh|csh)[^"]+)"'


def strip_carets(text: bytes):
    return bytes(i for i in text if i != ord('^'))


def deobfuscate_cmd(cmd: bytes):
    if b'^' in cmd:
        return strip_carets(cmd), 'unescape.shell.carets'
    return cmd, ''


@analyzer('shell.cmd')
def find_cmd_strings(data: bytes) -> List[Hit]:
    return find_and_deobfuscate(CMD_RE, data, deobfuscate_cmd)


@analyzer('shell.powershell')
def find_powershell_strings(data: bytes) -> List[Hit]:
    return find_and_deobfuscate(POWERSHELL_RE, data, deobfuscate_cmd, group=1)
