import binascii

from multidecoder.base64 import base64_search

def test_base64_search_empty():
    assert base64_search(b'') == []

def test_base64_search_abc():
    assert base64_search(binascii.b2a_base64(b'Some base64 encoded text')) == [b'Some base64 encoded text']

