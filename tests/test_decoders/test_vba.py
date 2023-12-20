import re

from multidecoder.decoders.vba import (
    CREATE_OBJECT_RE,
    find_createobject,
    find_strreverse,
)
from multidecoder.node import Node


def test_re_empty():
    assert not re.search(CREATE_OBJECT_RE, b"")


def test_re_wscript():
    assert re.search(CREATE_OBJECT_RE, b'CreateObject("WScript.Shell")')


def test_find_wscript():
    text = b'X = CreateObject("WScript.Shell")'
    assert find_createobject(text) == [
        Node(
            "vba.function.createobject",
            b'CreateObject("WScript.Shell")',
            "",
            4,
            len(text),
        )
    ]


def test_find_strreverse_empty():
    assert find_strreverse(b"") == []


def test_find_strreverse_duck():
    assert find_strreverse(b'StrReverse("kcud")')[0].value == b"duck"


def test_find_strreverse_endpoints():
    string = b'StrReverse("kcud")'
    hit = find_strreverse(string)[0]
    assert hit.start == 0
    assert hit.end == len(string)
