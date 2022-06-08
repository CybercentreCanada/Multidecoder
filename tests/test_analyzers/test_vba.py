import re

from multidecoder.analyzers.vba import CREATE_OBJECT_RE, find_createobject, find_strreverse
from multidecoder.hit import Hit


def test_re_empty():
    assert not re.search(CREATE_OBJECT_RE, b'')


def test_re_wscript():
    assert re.search(CREATE_OBJECT_RE, b'CreateObject("WScript.Shell")')


def test_find_wscript():
    text = b'X = CreateObject("WScript.Shell")'
    assert find_createobject(text) == [
        Hit(b'CreateObject("WScript.Shell")', '', 4, len(text))
    ]


def test_find_strreverse_empty():
    assert find_strreverse(b'') == []


def test_find_strreverse_duck():
    assert find_strreverse(b'StrReverse("kcud")')[0].value == b'duck'
