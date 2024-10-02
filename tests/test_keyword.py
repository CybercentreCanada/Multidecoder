import pytest

from multidecoder.keyword import find_all, find_keywords, is_mixed_case
from multidecoder.node import Node


@pytest.mark.parametrize(
    ("value", "raw", "expected_bool"),
    [
        (b"blah", b"blah", False),
        (b"BLAH", b"blah", False),
        (b"BLAH", b"BLAH", False),
        (b"blah", b"BLAH", False),
        (b"Blah", b"Blah", False),
        (b"BLah", b"Blah", True),
        (b"Blah", b"BLah", True),
    ],
)
def test_is_mixed_case(value, raw, expected_bool):
    assert is_mixed_case(value, raw) is expected_bool


@pytest.mark.parametrize(
    ("keyword", "data", "expected_list_of_ints"),
    [
        (b"yabadabadoo", b"yabadabadoo", [0]),
        (b"daba", b"yabadabadoo", []),
        (b"daba", b"yaba;daba+doo", [5]),
        (b"yaba", b"yaba;daba+doo", [0]),
        (b"doo", b"yaba;daba+doo", [10]),
    ],
)
def test_find_all(keyword, data, expected_list_of_ints):
    assert find_all(keyword, data) == expected_list_of_ints


@pytest.mark.parametrize(
    ("label", "keywords", "data", "expected_list_of_nodes"),
    [
        # Example where daba is not returned
        ("label", [b"yabadabadoo", b"daba"], b"yabadabadoo", [Node("label", b"yabadabadoo", "", 0, 11)]),
        # Example where all keywords are returned
        (
            "label",
            [b"yabadabadoo", b"yaba", b"daba", b"doo"],
            b"yaba;daba+doo",
            [Node("label", b"yaba", "", 0, 4), Node("label", b"daba", "", 5, 9), Node("label", b"doo", "", 10, 13)],
        ),
        # Example where all keywords are returned, with MixedCase hit
        (
            "label",
            [b"YABA", b"DaBa", b"doo"],
            b"YaBa;DaBa+doo",
            [
                Node("label", b"YABA", "MixedCase", 0, 4),
                Node("label", b"DaBa", "", 5, 9),
                Node("label", b"doo", "", 10, 13),
            ],
        ),
    ],
)
def test_find_keywords(label, keywords, data, expected_list_of_nodes):
    assert find_keywords(label, keywords, data) == expected_list_of_nodes
