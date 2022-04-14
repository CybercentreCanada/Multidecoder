
import regex as re

import itertools
from multidecoder.analyzers.encoding import UTF16_RE, find_utf16

test_bytes = bytes(itertools.chain([0x9, 0xA, 0xB, 0xC, 0xD], range(0x20, 0x7F), range(0xA0, 0x100)))
test = bytes(itertools.chain(*zip(test_bytes, [0]*256)))


def test_UTF16_RE_empty():
    assert not re.match(UTF16_RE, b'')


def test_UTF16_RE_latin1():
    match = re.match(UTF16_RE, test)
    assert match
    assert match.span() == (0, len(test))


def test_find_utf16_latin1():
    assert find_utf16(test)[0].value == test_bytes.decode('latin-1').encode()
