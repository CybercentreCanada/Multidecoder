from __future__ import annotations

from typing import TYPE_CHECKING

from multidecoder.node import Node

if TYPE_CHECKING:
    from typing import Iterable

MIXED_CASE_OBF = "MixedCase"


def is_mixed_case(expected: bytes, found: bytes) -> bool:
    # Keyword is mixed case if it has an unexpected uppercase character, unless it's all uppercase.
    # Doing sequences of alphabetic characters seperately to handle regestry keys and paths better.
    in_word = False
    all_upper = True
    good_case = True
    for byte_found, byte_expected in zip(found, expected):
        if chr(byte_found).isalpha():
            in_word = True
            found_upper = chr(byte_found).isupper()
            expected_upper = chr(byte_expected).isupper()
            all_upper = all_upper and found_upper
            good_case = good_case and (expected_upper or not found_upper)
        elif in_word:
            if not all_upper and not good_case:
                return True
            in_word = False
            all_upper = True
            good_case = True
    return (not all_upper and not good_case) if in_word else False


def find_keywords(label: str, keywords: Iterable[bytes], data: bytes) -> list[Node]:
    lower = data.lower()
    return [
        Node(
            label,
            keyword,
            MIXED_CASE_OBF if is_mixed_case(keyword, data[start : start + len(keyword)]) else "",
            start,
            start + len(keyword),
        )
        for keyword in keywords
        for start in find_all(keyword.lower(), lower)
    ]


def find_all(keyword: bytes, data: bytes) -> list[int]:
    if not keyword:
        return []
    starts = []
    start = data.find(keyword)
    while start >= 0:
        end = start + len(keyword)
        if (start == 0 or not chr(data[start - 1]).isalnum()) and (end == len(data) or not chr(data[end]).isalnum()):
            starts.append(start)
        start = data.find(keyword, end)
    return starts
