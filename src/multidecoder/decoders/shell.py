from __future__ import annotations

import binascii

import regex as re

from multidecoder.node import Node
from multidecoder.registry import decoder

CMD_RE = rb'(?i)("(?:C:\\WINDOWS\\system32\\)?\bcmd(?:.exe)?"|(?:C:\\Windows\\System32\\)?\bc\^?m\^?d\b)[^\x00]*'
POWERSHELL_INDICATOR_RE = (
    rb'(?i)(?:^|/c|/k|/r|[;,=&\'"({\\])\s*'
    rb"(\^?\bp\^?(?:o\^?w\^?e\^?r\^?s\^?h\^?e\^?l\^?l|w\^?s\^?h)(?:\^?.\^?e\^?x\^?e)?)\b"
)
SH_RE = rb'"(\s*(?:sh|bash|zsh|csh)[^"]+)"'
ENC_RE = (
    rb"(?i)\"?(?:(?:\^?\s)*\^?(?:\s\^?-|/)[a-z^]+)*(?:\^?\s)*\^?(?:\s\^?-|/)\^?"
    rb"e\^?(?:c|n\^?(?:c\^?(?:o\^?(?:d\^?(?:e\^?(?:d\^?(?:c\^?(?:o\^?(?:m\^?(?:m\^?(?:a\^?(?:n\^?d?)?)?)?)?)?)?)?)?)?)?)?)?"
    rb"(?:\^?\s)+\^?[\"\']?[a-z0-9+/^]{4,}=?\^?=?\^?[\'\"]?"
)
POWERSHELL_ARGS_RE = rb"\s*(powershell|pwsh)?(.exe)?\s*((-|/)[^\s]+\s+)*"


def strip_carets(cmd: bytes) -> bytes:
    in_string = False
    out = []
    i = 0
    while i < len(cmd) - 1:
        character = cmd[i]
        if character == ord('"'):
            # Starts or ends a string
            in_string = not in_string
        elif character == ord("\r"):
            # Line break
            in_string = False  # Line breaks automatically end strings
        elif character == ord("^") and not in_string:
            # Skip and treat the next character literally
            i += 1
            if cmd[i] == ord("\r"):
                i += 2  # skip \r\n
        # Add the character (or next character if ^)
        out.append(cmd[i])
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
        full_cmd = match.group()
        start, end = match.span()
        parens = 0
        for i, char in enumerate(full_cmd):
            if char == ord(b")"):
                parens -= 1
            elif char == ord(b"("):
                parens += 1
            if parens < 0:
                full_cmd = full_cmd[:i]
                end = start + i
        deobfuscated, obfuscation = deobfuscate_cmd(full_cmd)

        split = deobfuscated.split()

        # The cmd binary/command itself is at split[0]
        if (not split[0].startswith(b'"') and split[0].endswith(b'"')) or (
            not split[0].startswith(b"'") and split[0].endswith(b"'")
        ):
            # Remove the trailing quotation
            split[0] = split[0][:-1]
            deobfuscated = b" ".join(split)

        cmd_string = Node("shell.cmd", deobfuscated, obfuscation, start, end)
        cmd_strings.append(cmd_string)
    return cmd_strings


@decoder
def find_powershell_strings(data: bytes) -> list[Node]:
    out = []
    # Find the string PowerShell, possibly obfuscated or shortened to pwsh
    for indicator in re.finditer(POWERSHELL_INDICATOR_RE, data):
        start = indicator.start(1)
        # Check for encoded parameter
        enc = re.match(ENC_RE, data, pos=indicator.end())
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
            pwsh_invocation, encoded = deobfuscated.rsplit(maxsplit=1)
            encoded = encoded.strip(b"'\"")
            if len(encoded) % 4 or b"^" in encoded:
                continue  # invalid base64
            try:
                b64 = binascii.a2b_base64(encoded).decode("utf-16", errors="ignore").encode()
            except binascii.Error:
                continue  # invalid base64
            pwsh_invocation = b" -".join(pwsh_invocation.split(b"/"))  # Replace cmd style args with powershell style
            args = pwsh_invocation.split()
            # The powershell binary/command itself is at args[0]
            if (not args[0].startswith(b'"') and args[0].endswith(b'"')) or (
                not args[0].startswith(b"'") and args[0].endswith(b"'")
            ):
                # Remove the trailing quotation
                args[0] = args[0][:-1]

            deobfuscated = b" ".join(args[:-1]) + b" -Command " + b64
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
    if not match:
        return powershell
    command = powershell[match.end() :]
    # Strip if the command starts and end with a double quote (34) or single quote (39)
    if len(command) > 1 and command[0] in [34, 39] and command[0] == command[-1]:
        command = command[1:-1]
    return command
