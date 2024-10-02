import pytest

from multidecoder.decoders.codec import find_utf16


@pytest.mark.parametrize(
    ("utf16", "decoded"),
    [
        (
            b"V\x00e\x00r\x00s\x00i\x00o\x00n\x00\x00\x00\x00\x001\x002\x00.\x003\x00.\x000\x00.\x000\x00\x00\x00",
            b"Version\x00\x0012.3.0.0",
        ),
    ],
)
def test_find_utf16(utf16, decoded):
    assert find_utf16(utf16)[0].value == decoded
