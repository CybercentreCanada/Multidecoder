from multidecoder.decoders.concat import find_concat
from multidecoder.node import Node


def test_concat_empty_plus():
    test = b'""+""'
    assert find_concat(test) == [Node("string", b"", "concatenation", 0, len(test))]


def test_concat_empty_and():
    test = b'""&""'
    assert find_concat(test) == [Node("string", b"", "concatenation", 0, len(test))]


def test_concat_spacing():
    test = b'  "  "  +  "  "  '
    assert find_concat(test) == [Node("string", b"    ", "concatenation", 2, len(test) - 2)]


def test_concat_newline():
    test = b'""\n+\n""'
    assert find_concat(test) == [Node("string", b"", "concatenation", 0, len(test))]


def test_concat_tab():
    test = b'""\t+\t""'
    assert find_concat(test) == [Node("string", b"", "concatenation", 0, len(test))]


def test_concat_vba_escape():
    test = b'"""" + """"'
    assert find_concat(test) == [Node("string", b'""""', "concatenation", 0, len(test))]


def test_concat_single_quote():
    test = b"'' + ''"
    assert find_concat(test) == [Node("string", b"", "concatenation", 0, len(test))]


def test_concate_single_quote_escape():
    test = b"''''+''''"
    assert find_concat(test) == [Node("string", b"''''", "concatenation", 0, len(test))]


def test_backslash_escape():
    test = b'"normal \\"nes"+"ted\\" string"'
    assert find_concat(test) == [Node("string", b'normal \\"nested\\" string', "concatenation", 0, len(test))]


def test_concat_multiple_concat():
    test = b'"first " + "second" + " third"'
    assert find_concat(test) == [Node("string", b"first second third", "concatenation", 0, len(test))]


def test_concat_mixed_multiple():
    test = b"\"double\" & 'single' & \"double\" & 'single'"
    assert find_concat(test) == [Node("string", b"doublesingledoublesingle", "concatenation", 0, len(test))]


def test_concat_xml():
    test = b'<t>"a"&amp;"pp"&amp;"lesauce"&amp;" is "&amp;"a"&amp;" del"&amp;"icio"&amp;"us foo"&amp;"d","</t>'
    assert find_concat(test) == [
        Node(
            "string",
            b"applesauce is a delicious food",
            "concatenation",
            3,
            len(test) - 6,
        )
    ]
