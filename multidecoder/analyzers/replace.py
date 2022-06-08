from __future__ import annotations

import regex as re

from multidecoder.analyzers.concat import STRING_RE
from multidecoder.hit import Hit
from multidecoder.registry import analyzer

REPLACE_RE = rb'(?i)(' + STRING_RE + rb')\.replace\(\s*(' + STRING_RE + rb')\s*,\s*(' + STRING_RE + rb')\s*\)'
VBA_REPLACE_RE = rb'(?i)replace\(\s*(' + STRING_RE + rb')\s*,\s*(' + STRING_RE + rb')\s*,\s*(' + STRING_RE + rb')\s*\)'
POWERSHELL_REPLACE_RE = rb'(?i)(' + STRING_RE + rb')\s*-replace\s*(' + STRING_RE + rb')\s*,\s*(' + STRING_RE + rb')'
JS_REGEX_REPLACE_RE = rb'(?i)(' + STRING_RE + rb')\.replace\(/([^/[\](){}\\.+*?^$,]+)/[gim]{0,3}\s*,\s*(' \
                      + STRING_RE + rb')\s*\)'


@analyzer('string')
def find_replace(data: bytes) -> list[Hit]:
    return [
        Hit(match.group(1)[1:-1].replace(match.group(2)[1:-1], match.group(3)[1:-1]), 'replace', *match.span())
        for match in re.finditer(REPLACE_RE, data)
    ]


@analyzer('powershell.string')
def find_powershell_replace(data: bytes) -> list[Hit]:
    return [
        Hit(match.group(1)[1:-1].replace(match.group(2)[1:-1], match.group(3)[1:-1]), 'replace', *match.span())
        for match in re.finditer(POWERSHELL_REPLACE_RE, data)
    ]


@analyzer('vba.string')
def find_vba_replace(data: bytes) -> list[Hit]:
    return [
        Hit(match.group(1)[1:-1].replace(match.group(2)[1:-1], match.group(3)[1:-1]), 'vba.replace', *match.span())
        for match in re.finditer(VBA_REPLACE_RE, data)
    ]


@analyzer('javascript.string')
def find_js_regex_replace(data: bytes) -> list[Hit]:
    return [
        Hit(match.group(1)[1:-1].replace(match.group(2), match.group(3)[1:-1]), 'replace', *match.span())
        for match in re.finditer(JS_REGEX_REPLACE_RE, data)
    ]
