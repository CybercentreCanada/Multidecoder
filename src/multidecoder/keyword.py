from __future__ import annotations

from typing import Iterable

from multidecoder.node import Node

MIXED_CASE_OBF = "MixedCase"


def is_mixed_case(value: bytes, raw: bytes) -> bool:
    # Mixed case is not possible if raw is entirely upper or lower-cased
    if raw.isupper() or raw.islower():
        return False

    for v, d in zip(raw, value):
        # Check for case discrepancy between byte characters
        if (chr(v).isupper() and not chr(d).isupper()) or (chr(v).islower() and not chr(d).islower()):
            return True

    return False


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
        if (start == 0 or not data[start - 1 : start].isalnum()) and (
            end == len(data) or not data[end : end + 1].isalnum()
        ):
            starts.append(start)
        start = data.find(keyword, start + len(keyword))
    return starts
