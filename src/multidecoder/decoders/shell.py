from __future__ import annotations

import binascii

import regex as re

from multidecoder.decoders.concat import DOUBLE_QUOTE_ESCAPES
from multidecoder.node import Node
from multidecoder.registry import decoder

CMD_RE = b"(?i)\\bc\\^?m\\^?d(?:" + DOUBLE_QUOTE_ESCAPES + rb'|[^)"\x00])*'
POWERSHELL_INDICATOR_RE = rb'(?i)(?:^|/c|/k|/r|[\s;,=&\'"])(\^?p\^?(?:o\^?w\^?e\^?r\^?s\^?h\^?e\^?l\^?l|w\^?s\^?h))\b'
SH_RE = rb'"(\s*(?:sh|bash|zsh|csh)[^"]+)"'
ENC_RE = (
    rb"(?i)\s\^?(?:-|/)\^?e\^?(?:c|n\^?(?:c\^?(?:o\^?(?:d\^?(?:e\^?(?:d\^?(?:c\^?(?:o\^?(?:m"
    rb"\^?(?:m\^?(?:a\^?(?:n\^?d?)?)?)?)?)?)?)?)?)?)?)?)?[\s^]+[\"\']?[a-z0-9+/^]{4,}=?\^?=?\^?[\'\"]?"
)
POWERSHELL_ARGS_RE = rb"\s*(powershell|pwsh)?(.exe)?\s*((-|/)[^\s]+\s+)*"


def strip_carets(cmd: bytes) -> bytes:
    in_string = False
    out = []
    i = 0
    while i < len(cmd) - 1:
        if cmd[i] == ord('"'):
            out.append(ord('"'))
            in_string = not in_string
            i += 1
        elif in_string or cmd[i] != ord("^"):
            out.append(cmd[i])
            i += 1
        elif cmd[i + 1] == ord("^"):
            i += 2
            out.append(ord("^"))
        elif cmd[i + 1] == ord("\r"):
            i += 3  # skip ^\r\n
        else:
            i += 1
    if i < len(cmd) and (cmd[i] != ord("^") or in_string):
        out.append(cmd[i])
    return bytes(out)


def deobfuscate_cmd(cmd: bytes) -> tuple[bytes, str]:
    stripped = strip_carets(cmd)
    return stripped, "unescape.shell.carets" if stripped != cmd else ""


@decoder
def find_cmd_strings(data: bytes) -> list[Node]:
    return [
        Node("shell.cmd", *deobfuscate_cmd(match.group()), *match.span())
        for match in re.finditer(CMD_RE, data)
        if match.group().lower().strip() not in (b"cmd", b"cmd.exe")
    ]


@decoder
def find_powershell_strings(data: bytes) -> list[Node]:
    out = []
    # Find the string PowerShell, possibly obfuscated or shortened to pwsh
    for indicator in re.finditer(POWERSHELL_INDICATOR_RE, data):
        start = indicator.start(1)
        # Check for encoded parameter
        enc = re.search(ENC_RE, data, pos=start)
        if enc:
            end = enc.end()
            powershell = data[start : enc.end()]
        else:
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
                end = len(data) - start
                powershell = data[start:]
        deobfuscated, obfuscation = deobfuscate_cmd(powershell)
        cmd_node = Node("shell.cmd", deobfuscated, obfuscation, start, end) if obfuscation else None
        if enc:
            split = deobfuscated.split()
            b64 = binascii.a2b_base64(_pad(split[-1].strip(b"'\""))).decode("utf-16", errors="ignore").encode()
            deobfuscated = b" ".join(split[:-2]) + b" -Command " + b64
            if cmd_node:
                cmd_node.children.append(
                    Node(
                        "shell.powershell",
                        deobfuscated,
                        "powershell.base64",
                        0,
                        len(deobfuscated),
                        cmd_node,
                    )
                )
                out.append(cmd_node)
            else:
                out.append(
                    Node(
                        "shell.powershell",
                        deobfuscated,
                        "powershell.base64",
                        start,
                        end,
                    )
                )
        else:
            if cmd_node:
                cmd_node.children.append(
                    Node(
                        "shell.powershell",
                        deobfuscated,
                        "",
                        0,
                        len(deobfuscated),
                        cmd_node,
                    )
                )
            out.append(Node("shell.powershell", deobfuscated, obfuscation, start, end))
    return out


def _pad(b64: bytes) -> bytes:
    padding = -len(b64) % 4
    if padding == 3:
        return b64[:-1]  # Corrupted end, just keep the valid part
    if padding:
        return b64 + b"=" * padding
    return b64


def get_cmd_command(cmd: bytes) -> bytes:
    # Find end of argument string
    end = re.search(rb"(?i)&|/(c|k|r)", cmd)
    if end is None:
        return b""
    arg = cmd[end.end() :].strip()
    if end.group() != b'"' and arg.startswith(b'"'):
        # strip leading and final quote
        index = arg.rfind(b'"')
        arg = arg[1:index] + arg[index + 1 :] if index > 0 else arg[1:]

    # return everything after the arguments
    return arg


def get_powershell_command(powershell: bytes) -> bytes:
    match = re.match(POWERSHELL_ARGS_RE, powershell)
    return powershell[match.end() :] if match else powershell
