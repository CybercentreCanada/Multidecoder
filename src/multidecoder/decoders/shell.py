from __future__ import annotations

import binascii

import regex as re

from multidecoder.decoders.base64 import pad_base64
from multidecoder.node import Node
from multidecoder.registry import decoder

CMD_RE = rb"(?i)\bc\^?m\^?d\^?\b[^)\x00]*"
POWERSHELL_INDICATOR_RE = (
    rb'(?i)(?:^|/c|/k|/r|[\s;,=&\'"])?\b(\^?p\^?(?:o\^?w\^?e\^?r\^?s\^?h\^?e\^?l\^?l|w\^?s\^?h))\b'
)
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
    cmd_strings = []
    for match in re.finditer(CMD_RE, data):
        if match.group().lower().strip() not in (b"cmd", b"cmd.exe"):
            deobfuscated, obfuscation = deobfuscate_cmd(match.group())

            split = deobfuscated.split()

            # The cmd binary/command itself is at split[0]
            if (not split[0].startswith(b'"') and split[0].endswith(b'"')) or (
                not split[0].startswith(b"'") and split[0].endswith(b"'")
            ):
                # Remove the trailing quotation
                split[0] = split[0][:-1]
                deobfuscated = b" ".join(split)

            cmd_string = Node("shell.cmd", deobfuscated, obfuscation, *match.span())
            cmd_strings.append(cmd_string)
    return cmd_strings


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
            b64 = binascii.a2b_base64(pad_base64(split[-1].strip(b"'\""))).decode("utf-16", errors="ignore").encode()

            # The powershell binary/command itself is at split[0]
            if (not split[0].startswith(b'"') and split[0].endswith(b'"')) or (
                not split[0].startswith(b"'") and split[0].endswith(b"'")
            ):
                # Remove the trailing quotation
                split[0] = split[0][:-1]

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
