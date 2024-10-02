import binascii

import pytest
import regex as re

from multidecoder.decoders.base64 import BASE64_RE, find_atob, find_base64, find_FromBase64String, pad_base64
from multidecoder.node import Node

# -- pad_base64 --


@pytest.mark.parametrize(
    ("base64", "padded"),
    [
        (b"a", b""),
        (b"aa", b"aa=="),
        (b"aaa", b"aaa="),
        (b"aaaa", b"aaaa"),
    ],
)
def test_pad_base64(base64, padded):
    assert pad_base64(base64) == padded


# -- find_atob --


@pytest.mark.parametrize(
    ("atob", "decoded"),
    [
        (b"atob('YXRvYiB0ZXN0IHRleHQ=')", b"atob test text"),
        (b'atob("YXRvYiB0ZXN0IHRleHQ=")', b"atob test text"),
    ],
)
def test_atob(atob, decoded):
    assert find_atob(atob)[0].value == decoded


# -- find_base64 --


def test_empty():
    assert find_base64(b"") == []


def test_hex():
    assert find_base64(b"0123456789abcdef") == []
    assert find_base64(b"2fd4e1c67a2d28fced849ee1bb76e7391b93eb12") == []


def test_CamelCase():
    assert find_base64(b"CamelCaseTesting") == []
    assert find_base64(b"WakeAllConditionVariable, GetUserDefaultUILanguage") == []


def test_url():
    assert find_base64(b"http://schemas.microsoft.com/SMI/2016/WindowsSettings") == []


def test_base64_re_matches_equals():
    ex = b"bmljZSBkYXksIGlzbid0IGl0Pw=="
    match = re.search(BASE64_RE, ex)
    assert match
    assert match.group() == ex


ENCODED = binascii.b2a_base64(b"Some base64 encoded text")
TEST_STRINGS = {
    ENCODED: [Node("", b"Some base64 encoded text", "encoding.base64", 0, 32)],
    b"lorem ipsum lorum asdf\nhjkl\nASDF\nasdf\nhjkl\nASDF\n44==lorum ipsum": [
        Node(
            "",
            b"j\xc7_\x869%\x01 \xc5j\xc7_\x869%\x01 \xc5\xe3",
            "encoding.base64",
            18,
            52,
        )
    ],
}


def test_base64_search_texts():
    for data, expected in TEST_STRINGS.items():
        response = find_base64(data)
        assert response == expected, f"{data} Failed"


# -- FromBase64String --


@pytest.mark.parametrize(
    ("data", "result"),
    [
        (
            b"FromBase64String('ZHVjaw==')",
            [
                Node(
                    type_="powershell.bytes",
                    value=b"duck",
                    obfuscation="encoding.base64",
                    start=0,
                    end=28,
                )
            ],
        ),
        (
            b'FromBase64String("ZHVjaw==")',
            [
                Node(
                    type_="powershell.bytes",
                    value=b"duck",
                    obfuscation="encoding.base64",
                    start=0,
                    end=28,
                )
            ],
        ),
        (
            b"[System.Convert]::FromBase64String('ZHVjaw==')",
            [
                Node(
                    type_="powershell.bytes",
                    value=b"duck",
                    obfuscation="encoding.base64",
                    start=0,
                    end=46,
                )
            ],
        ),
        (
            b'[System.Convert]::FromBase64String("ZHVjaw==")',
            [
                Node(
                    type_="powershell.bytes",
                    value=b"duck",
                    obfuscation="encoding.base64",
                    start=0,
                    end=46,
                )
            ],
        ),
    ],
)
def test_fromb64string_no_xor(data, result):
    assert find_FromBase64String(data) == result


def test_fromb64string_xor():
    test = b"FromBase64String('R1ZASA==')\n-bxor 35"
    assert find_FromBase64String(test) == [
        Node(
            type_="powershell.bytes",
            value=b"GV@H",
            obfuscation="encoding.base64",
            start=0,
            end=test.find(b"\n"),
            children=[Node("powershell.bytes", b"duck", "cipher.xor35", 0, 4)],
        )
    ]
