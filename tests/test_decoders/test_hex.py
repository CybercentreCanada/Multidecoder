import regex as re
from multidecoder.decoders.hex import HEX_RE, find_FromHexString, find_hex
from multidecoder.node import Node


def test_empty():
    assert not re.search(HEX_RE, b"")


def test_text():
    assert not re.search(HEX_RE, b"Here is a short segment of english text with arbitrary words.")


def test_hex():
    assert re.search(HEX_RE, b"some encoded text".hex().encode())


def test_find_hex():
    assert find_hex(b"some encoded text".hex().encode())[0].value == b"some encoded text"


# -- FromHexString --


def test_fromhexstring_no_xor():
    test = b"FromHexString('6475636b20676f657320717561636b')"
    test2 = b"[System.Convert]::FromHexString('6475636b20676f657320717561636b')"
    assert find_FromHexString(test) == [
        Node(
            type_="powershell.bytes",
            value=b"duck goes quack",
            obfuscation="encoding.hexidecimal",
            start=0,
            end=len(test),
        )
    ]
    assert find_FromHexString(test2) == [
        Node(
            type_="powershell.bytes",
            value=b"duck goes quack",
            obfuscation="encoding.hexidecimal",
            start=0,
            end=len(test2),
        )
    ]


def test_fromhexstring_xor():
    test = b"FromHexString('4756404803444c4650035256424048')\n-bxor 35"
    assert find_FromHexString(test) == [
        Node(
            type_="powershell.bytes",
            value=b"GV@H\x03DLFP\x03RVB@H",
            obfuscation="encoding.hexidecimal",
            start=0,
            end=test.find(b"\n"),
            children=[Node("powershell.bytes", b"duck goes quack", "cipher.xor35", 0, 15)],
        )
    ]
