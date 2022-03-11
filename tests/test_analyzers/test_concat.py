
from multidecoder.analyzers.concat import find_concat
from multidecoder.hit import Hit


def test_concat_empty_plus():
    test = b'""+""'
    assert find_concat(test) == [Hit(b'', 0, len(test), 'concatenation')]


def test_concat_empty_and():
    test = b'""&""'
    assert find_concat(test) == [Hit(b'', 0, len(test), 'concatenation')]


def test_concat_spacing():
    test = b'  "  "  +  "  "  '
    assert find_concat(test) == [Hit(b'    ', 2, len(test)-2, 'concatenation')]


def test_concat_newline():
    test = b'""\n+\n""'
    assert find_concat(test) == [Hit(b'', 0, len(test), 'concatenation')]


def test_concat_tab():
    test = b'""\t+\t""'
    assert find_concat(test) == [Hit(b'', 0, len(test), 'concatenation')]


def test_concat_vba_escape():
    test = b'"""" + """"'
    assert find_concat(test) == [Hit(b'""""', 0, len(test), 'concatenation')]


def test_concat_single_quote():
    test = b"'' + ''"
    assert find_concat(test) == [Hit(b'', 0, len(test), 'concatenation')]


def test_concate_single_quote_escape():
    test = b"''''+''''"
    assert find_concat(test) == [Hit(b"''''", 0, len(test), 'concatenation')]


def test_backslash_escape():
    test = b'"normal \\"nes"+"ted\\" string"'
    assert find_concat(test) == [Hit(b'normal \\"nested\\" string', 0, len(test), 'concatenation')]


def test_concat_multiple_concat():
    test = b'"first " + "second" + " third"'
    assert find_concat(test) == [Hit(b'first second third', 0, len(test), 'concatenation')]


def test_concat_mixed_multiple():
    test = b'"double" & \'single\' & "double" & \'single\''
    assert find_concat(test) == [Hit(b'doublesingledoublesingle', 0, len(test), 'concatenation')]