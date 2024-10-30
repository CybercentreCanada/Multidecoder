import pytest

from multidecoder.decoders.powershell import POWERSHELL_BYTES_TYPE, find_powershell_bytes
from multidecoder.node import Node


def to_powershell(data: bytes) -> bytes:
    return ", ".join(hex(byte) for byte in data).encode()


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        (
            to_powershell(b"duck" * 200) + b"-bxor",
            [
                Node(
                    POWERSHELL_BYTES_TYPE,
                    b"duck" * 200,
                    "",
                    0,
                    4798,
                    children=[Node(POWERSHELL_BYTES_TYPE, b"\x00" * 800, "cipher.multibyte_xor", 0, 800)],
                )
            ],
        ),
        (
            to_powershell(b"a" * 600) + b" -bxor 65",
            [
                Node(
                    POWERSHELL_BYTES_TYPE,
                    b"a" * 600,
                    "",
                    0,
                    3598,
                    children=[Node(POWERSHELL_BYTES_TYPE, b" " * 600, "cipher.xor65", 0, 600)],
                )
            ],
        ),
    ],
)
def test_find_powershell_bytes(data: bytes, expected):
    assert find_powershell_bytes(data) == expected
