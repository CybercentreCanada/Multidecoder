import pytest

from multidecoder.decoders.chr import find_chr


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"chr()",
    ],
)
def test_find_chr_empty(data):
    assert find_chr(data) == []


@pytest.mark.parametrize(
    ("data", "value"),
    [
        (b"chr(65)", b"A"),
        (b"chrw(65)", b"A"),
        (b"chrb(65)", b"A"),
    ],
)
def test_find_chr_a(data, value):
    assert find_chr(data)[0].value == value


def test_find_chr_duck():
    assert find_chr(b"chr(69)chr(117)chr(99)chr(107)")
