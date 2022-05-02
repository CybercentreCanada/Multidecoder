from __future__ import annotations

import regex as re
import binascii

from multidecoder.analyzers.concat import DOUBLE_QUOTE_ESCAPES
from multidecoder.hit import Hit, find_and_deobfuscate
from multidecoder.registry import analyzer


CMD_RE = rb'(?i)\bc\^?m\^?d(?:' + DOUBLE_QUOTE_ESCAPES + rb'|[^)"])+'
POWERSHELL_INDICATOR_RE = rb'(?i)(?:^|/c|/k|[\s;,=\'"])(\^?p\^?(?:o\^?w\^?e\^?r\^?s\^?h\^?e\^?l\^?l|w\^?s\^?h))\b'
SH_RE = rb'"(\s*(?:sh|bash|zsh|csh)[^"]+)"'
ENC_RE = rb'(?i)\s\^?(?:-|/)\^?e\^?(?:c|n\^?(?:c\^?(?:o\^?(?:d\^?(?:e\^?(?:d\^?(?:c\^?(?:o\^?(?:m' \
         rb'\^?(?:m\^?(?:a\^?(?:n\^?d?)?)?)?)?)?)?)?)?)?)?)?)?[\s^]+([a-z0-9+/^]{4,}=?\^?=?\^?)'
POWERSHELL_ARGS_RE = rb'\s*(powershell|pwsh)?(.exe)?\s*((-|/)[^\s]+\s+)*'


def strip_carets(cmd: bytes) -> bytes:
    in_string = False
    out = []
    i = 0
    while i < len(cmd)-1:
        if cmd[i] == ord('"'):
            out.append(ord('"'))
            in_string = not in_string
            i += 1
        elif in_string or cmd[i] != ord('^'):
            out.append(cmd[i])
            i += 1
        elif cmd[i+1] == ord('^'):
            i += 2
            out.append(ord('^'))
        elif cmd[i+1] == ord('\r'):
            i += 3  # skip ^\r\n
        else:
            i += 1
    if i < len(cmd) and (cmd[i] != ord('^') or in_string):
        out.append(cmd[i])
    return bytes(out)


def deobfuscate_cmd(cmd: bytes):
    stripped = strip_carets(cmd)
    return stripped, 'unescape.shell.carets' if stripped != cmd else ''


@analyzer('shell.cmd')
def find_cmd_strings(data: bytes) -> list[Hit]:
    return find_and_deobfuscate(CMD_RE, data, deobfuscate_cmd)


@analyzer('shell.powershell')
def find_powershell_strings(data: bytes) -> list[Hit]:
    out = []
    # Find the string PowerShell, possibly obfuscated or shortened to pwsh
    for indicator in re.finditer(POWERSHELL_INDICATOR_RE, data):
        # Check for encoded parameter
        start = indicator.start(1)
        enc = re.search(ENC_RE, data, pos=start)
        if enc:
            powershell = data[start:enc.end()]
            deobfuscated, ob = deobfuscate_cmd(powershell)
            split = re.split(rb'\s+', deobfuscated)
            b64 = (binascii.a2b_base64(_pad(split[-1]))
                           .decode('utf-16', errors='ignore')
                           .encode())
            deobfuscated = b' '.join(split[:-2]) + b' -Command ' + b64
            obfuscation = ob + ('/>' if ob else '') + 'powershell.base64'
            out.append(Hit(deobfuscated, obfuscation, start, enc.end()))
            continue
        # Look back to find the start of the string or FOR loop
        bound_match = re.search(rb'(\'\(|[\'"])', data[start::-1])
        if bound_match:
            bound = bound_match.group()
            assert bound in (b"'(", b'"', b"'")
            if bound == b"'(":
                # In a cmd FOR loop, find the end paren
                end = data.find(b"')", start)
            elif bound == b'"':
                # In a double quoted string, find the end quote
                end = data.find(b'"', start)
            else:
                # In a single quoted string, find the end quote
                end = data.find(b"'", start)
            powershell = data[start:end]
        else:
            # No recognizable context, assume rest of file is all powershell
            end = len(data)-start
            powershell = data[start:]
        deobfuscated, obfuscation = deobfuscate_cmd(powershell)
        out.append(Hit(deobfuscated, obfuscation, start, end))
    return out


def _pad(b64: bytes) -> bytes:
    padding = -len(b64) % 4
    if padding == 3:
        return b64[:-1]  # Corrupted end, just keep the valid part
    elif padding:
        return b64 + b'='*padding
    else:
        return b64


def get_cmd_command(cmd: bytes):
    # Find end of argument string
    lcmd = cmd.lower()
    arg_end = len(cmd)
    c = lcmd.find(b'/c')
    if c > 0:
        arg_end = min(arg_end, c+2)
    k = lcmd.find(b'/k')
    if k > 0:
        arg_end = min(arg_end, k+2)
    amp = lcmd.find(b'&')
    if amp > 0:
        arg_end = min(arg_end, amp+1)

    # return everything after the arguments
    return cmd[arg_end:]


def get_powershell_command(powershell: bytes):
    match = re.match(POWERSHELL_ARGS_RE, powershell)
    if match:
        return powershell[match.end():]
    else:
        return powershell
