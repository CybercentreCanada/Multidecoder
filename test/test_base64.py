import binascii

from multidecoder.analyzers.base64 import find_base64

def test_find_base64_empty():
    assert find_base64(b'') == []

def test_find_base64_hex():
    assert find_base64(b'0123456789abcdef') == []
    assert find_base64(b'2fd4e1c67a2d28fced849ee1bb76e7391b93eb12') == []

def test_find_base64_camel():
    assert find_base64(b'CamelCaseTesting') == []

ENCODED = binascii.b2a_base64(b'Some base64 encoded text')
TEST_STRINGS = {
    ENCODED: [(b'Some base64 encoded text', 0, 32)],
    b'lorem ipsum lorum asdf\nhjkl\nASDF\nasdf\nhjkl\nASDF\n44==lorum ipsum':
        [(b'j\xc7_\x869%\x01 \xc5j\xc7_\x869%\x01 \xc5\xe3', 18, 52)]
}
def test_base64_search_texts():
    for data, expected in TEST_STRINGS.items():
        response = find_base64(data)
        assert response == expected, f'{data} Failed'
