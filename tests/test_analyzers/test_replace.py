from multidecoder.decoders.replace import (
    find_js_regex_replace,
    find_powershell_replace,
    find_replace,
    find_vba_replace,
)


def test_find_replace_emtpy():
    assert find_replace(b"") == []


def test_find_powershell_replace_empty():
    assert find_powershell_replace(b"") == []


def test_find_vba_replace_empty():
    assert find_vba_replace(b"") == []


def test_find_js_regex_replace():
    assert find_js_regex_replace(b"") == []


def test_find_replace_duck():
    assert find_replace(b'"duduckck".replace("duck", "")')[0].value == b"duck"


def test_find_powershell_replace_duck():
    assert find_powershell_replace(b'"duduckck"-replace"duck",""')[0].value == b"duck"


def test_find_vba_replace_duck():
    assert find_vba_replace(b'replace("duduckck","duck","")')[0].value == b"duck"


def test_find_js_regex_replace_duck():
    assert find_js_regex_replace(b'"duduckck".replace(/duck/,"")')[0].value == b"duck"
