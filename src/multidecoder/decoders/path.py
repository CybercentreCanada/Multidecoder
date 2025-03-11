from __future__ import annotations

import ntpath

import regex as re

from multidecoder.decoders.filename import EXT_MAP
from multidecoder.decoders.network import is_domain, parse_ip
from multidecoder.hit import regex_hits
from multidecoder.node import Node
from multidecoder.registry import decoder

# Posix style paths
PATH_RE = rb"[.]?[.]?/(\w{3,}/)+[\w.]{3,}"

# Windows Paths
# See https://learn.microsoft.com/en-us/dotnet/standard/io/file-path-formats
WINDOWS_PATH_RE = (
    rb"(?i)(?:\\\\[.?]\\(?:[a-z]:\\|UNC\\[\w.-]+\\(?:[a-z][$]\\)?|Volume\{[a-z0-9-]{36}\}\\)?"  # DOS device path
    rb"|\\\\[\w.-]+(?:@SSL)?(?:@\d{,5})?\\(?:[a-z][$]\\)?"  # UNC path
    rb"|[a-z]:\\?|\\)?"  # absolute or drive relative path
    rb"(?:(?:[.]|[.][.]|[\w.-]{3,})\\)+"  # path segments
    rb"[\w.-]{3,}"  # filename
)


@decoder
def find_path(data: bytes) -> list[Node]:
    return regex_hits("path", PATH_RE, data)


@decoder
def find_windows_path(data: bytes) -> list[Node]:
    output = []
    for match in re.finditer(WINDOWS_PATH_RE, data):
        path = match.group()
        length = len(path)
        path = ntpath.normpath(path)
        obfuscation = "windows.dotpath" if len(path) < length else ""
        children = []
        segments = path.split(b"\\")
        if path.startswith((Rb"\\.", Rb"\\?")):
            path_type = "windows.device.path"
            if segments[3].upper() == b"UNC":
                hostname = segments[4].split(b"@", maxsplit=1)[0]
                try:
                    children.append(parse_ip(hostname).shift(8))
                except ValueError:
                    if is_domain(hostname):
                        children.append(Node("network.domain", hostname, "", 8, 8 + len(hostname)))
        elif path.startswith(Rb"\\"):
            path_type = "windows.unc.path"
            hostname = segments[2].split(b"@", maxsplit=1)[0]
            try:
                children.append(parse_ip(hostname).shift(2))
            except ValueError:
                if is_domain(hostname):
                    children.append(Node("network.domain", hostname, "", 2, 2 + len(hostname)))
        else:
            path_type = "windows.path"
        filename = segments[-1]
        basename, extension = ntpath.splitext(filename)
        if extension:
            type_ = EXT_MAP.get(extension.lower(), "filename")
            children.append(Node(type_, filename, "", len(path) - len(filename), len(path)))
        output.append(Node(path_type, path, obfuscation, *match.span(), children=children))
    return output
