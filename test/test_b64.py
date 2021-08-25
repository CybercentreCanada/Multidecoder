import binascii

from multidecoder.base64 import base64_search

def test_base64_search_empty():
    assert base64_search(b'') == {}

ENCODED = binascii.b2a_base64(b'Some base64 encoded text')
TEST_STRINGS = {
    ENCODED: {ENCODED.strip(): b'Some base64 encoded text'},
    b'lorem ipsum lorum asdf\nhjkl\nASDF\n44==lorum ipsum':
        {b'asdf\nhjkl\nASDF\n44==': b'j\xc7_\x869%\x01 \xc5\xe3'}
}
def test_base64_search_texts():
    for text, expected in TEST_STRINGS.items():
        response = base64_search(text)
        assert response == expected, f'{text} Failed'
