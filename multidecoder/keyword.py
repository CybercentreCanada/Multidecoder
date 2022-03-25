from __future__ import annotations

from typing import Iterable

from multidecoder.hit import Hit


def is_mixed_case(value: bytes, raw: bytes) -> bool:
    return any(chr(v).isupper() and not chr(d).isupper()
               for v, d in zip(raw, value)) and not raw.isupper()


def find_keywords(keywords: Iterable[bytes], data: bytes) -> list[Hit]:
    lower = data.lower()
    return [
        Hit(keyword,
            'MixedCase' if is_mixed_case(keyword, data[start:start+len(keyword)]) else '',
            start,
            start+len(keyword))
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
        if (start == 0 or not data[start-1:start].isalnum()) and (end == len(data) or not data[end:end+1].isalnum()):
            starts.append(start)
        start = data.find(keyword, start+len(keyword))
    return starts
