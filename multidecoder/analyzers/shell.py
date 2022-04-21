from __future__ import annotations

import regex as re
import binascii

from multidecoder.analyzers.concat import DOUBLE_QUOTE_ESCAPES
from multidecoder.hit import Hit, find_and_deobfuscate
from multidecoder.registry import analyzer


CMD_RE = rb'(?i)\bc\^?m\^?d(?:' + DOUBLE_QUOTE_ESCAPES + rb'|[^)"])+'
POWERSHELL_RE = rb'(?i)"([\s^]*p^?(?:o^?w^?e^?r^?s^?h^?e^?l^?l|w^?s^?h)[^"]+)"'
SH_RE = rb'"(\s*(?:sh|bash|zsh|csh)[^"]+)"'
ENC_RE = rb'(?i)(?:-|/)e(?:n(?:c(?:o(?:d(?:e(?:d(?:c(?:o(?:m(?:m(?:a(?:nd?)?)?)?)?)?)?)?)?)?)?)?|c)' \
         rb'?[\s]+([a-z0-9+/]{4,}=?=?)'


def strip_carets(cmd: bytes) -> bytes:
    return re.sub(rb'(\^+)(/r/n)?',
                  lambda match: b'^' * (len(match.group(1)) // 2),
                  cmd)


def deobfuscate_cmd(cmd: bytes):
    stripped = strip_carets(cmd)
    return stripped, 'unescape.shell.carets' if stripped != cmd else ''


@analyzer('shell.cmd')
def find_cmd_strings(data: bytes) -> list[Hit]:
    return find_and_deobfuscate(CMD_RE, data, deobfuscate_cmd)


@analyzer('shell.powershell')
def find_powershell_strings(data: bytes) -> list[Hit]:
    out = []
    for match in re.finditer(POWERSHELL_RE, data):
        obfuscation = []
        deobfuscated, ob = deobfuscate_cmd(match.group(1))
        if ob:
            obfuscation.append(ob)
        enc = re.search(ENC_RE, deobfuscated)
        if enc:
            b64 = (binascii.a2b_base64(_pad(enc.group(1)))
                           .decode('utf-16', errors='ignore')
                           .encode())
            deobfuscated = deobfuscated[:enc.start()] + b64 + deobfuscated[enc.end():]
            obfuscation.append('powershell.base64')
        out.append(Hit(deobfuscated, '/>'.join(obfuscation), match.start(), match.end()))
    return out


def _pad(b64: bytes) -> bytes:
    padding = -len(b64) % 4
    if padding == 3:
        return b64[:-1]  # Corrupted end, just keep the valid part
    elif padding:
        return b64 + b'='*padding
    else:
        return b64
