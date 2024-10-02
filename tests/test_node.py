import pytest

from multidecoder.node import Node

DATA1 = b"12345HERE WE ARE54321"
EXAMPLE1 = Node(
    "",
    DATA1,
    "",
    0,
    len(DATA1),
    children=[Node("test", b"And now for something completely different.", "different", 5, 16)],
)


def test_original_no_parent():
    data = b"unmodified data"
    assert Node("test", data, "", 0, len(data)).original == data


def test_original_parent():
    assert EXAMPLE1.children[0].original == b"HERE WE ARE"


@pytest.mark.parametrize(
    ("node", "flat"),
    [
        (EXAMPLE1, b"12345And now for something completely different.54321"),
        (Node("", b"abc", "", 0, 3, children=[Node("", b"FIRST", "", 0, 2), Node("", b"SECOND", "", 1, 3)]), b"FIRSTc"),
        (Node("", b"abc", "", 0, 3, children=[Node("", b"FIRST", "", 0, 3), Node("", b"SECOND", "", 0, 3)]), b"FIRST"),
    ],
)
def test_flatten(node, flat):
    assert node.flatten() == flat
