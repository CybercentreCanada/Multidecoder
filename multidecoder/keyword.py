from __future__ import annotations

from typing import Iterable

from multidecoder.hit import Hit

def find_keywords(keywords: Iterable[bytes], data: bytes) -> list[Hit]:
    data = data.lower()
    return [
        Hit(keyword, start, start+len(keyword))
        for keyword in keywords
        for start in find_all(keyword.lower(), data)
    ]

def find_all(keyword: bytes, data:bytes) -> list[int]:
    if not keyword:
        return []
    starts = []
    start = data.find(keyword)
    while start >= 0:
        starts.append(start)
        start = data.find(keyword, start+len(keyword))
    return starts