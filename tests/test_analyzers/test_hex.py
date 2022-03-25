import regex as re

from multidecoder.analyzers.hex import HEX_RE, find_hex


def test_empty():
    assert not re.search(HEX_RE, b'')


def test_text():
    assert not re.search(HEX_RE, b'Here is a short segment of english text with arbitrary words.')


def test_hex():
    assert re.search(HEX_RE, b'some encoded text'.hex().encode())


def test_find_hex():
    assert find_hex(b'some encoded text'.hex().encode())[0].value == b'some encoded text'
