import binascii
import regex as re

from multidecoder.analyzers.base64 import find_base64, BASE64_RE


def test_empty():
    assert find_base64(b'') == []


def test_hex():
    assert find_base64(b'0123456789abcdef') == []
    assert find_base64(b'2fd4e1c67a2d28fced849ee1bb76e7391b93eb12') == []


def test_CamelCase():
    assert find_base64(b'CamelCaseTesting') == []
    assert find_base64(b'WakeAllConditionVariable, GetUserDefaultUILanguage') == []


def test_url():
    assert find_base64(b'http://schemas.microsoft.com/SMI/2016/WindowsSettings') == []


def test_base64_re_matches_equals():
    ex = b'bmljZSBkYXksIGlzbid0IGl0Pw=='
    match = re.search(BASE64_RE, ex)
    assert match
    assert match.group() == ex


ENCODED = binascii.b2a_base64(b'Some base64 encoded text')
TEST_STRINGS = {
    ENCODED: [(b'Some base64 encoded text', 'decoded.base64', 0, 32)],
    b'lorem ipsum lorum asdf\nhjkl\nASDF\nasdf\nhjkl\nASDF\n44==lorum ipsum':
        [(b'j\xc7_\x869%\x01 \xc5j\xc7_\x869%\x01 \xc5\xe3', 'decoded.base64', 18, 52)]
}


def test_base64_search_texts():
    for data, expected in TEST_STRINGS.items():
        response = find_base64(data)
        assert response == expected, f'{data} Failed'
