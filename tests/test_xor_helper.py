import pytest

from multidecoder.node import Node
from multidecoder.xor_helper import apply_xor_key, get_xorkey


@pytest.mark.parametrize(
    ("data", "expected_xorkey"),
    [
        (b"blah", None),
        (b"blah-xor35", 35),
        (b"blah\n\t -xor\n\t 35", 35),
        (b"blah -bxor 35", 35),
        (b"blah -bxor 3535", 353),
    ],
)
def test_get_xorkey(data, expected_xorkey):
    assert get_xorkey(data) == expected_xorkey


@pytest.mark.parametrize(
    ("data", "expected_child_node"),
    [
        (b"AOBK", Node("powershell.bytes", b"blah", "cipher.xor35", 0, 4)),
    ],
)
def test_apply_xor_key(data, expected_child_node):
    parent_node = Node("", b"abc", "", 0, 3)
    xorkey = 35
    assert apply_xor_key(xorkey, data, parent_node, "powershell.bytes").children[0] == expected_child_node
