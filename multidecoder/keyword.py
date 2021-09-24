
from typing import Iterable, List

from multidecoder.hit import Hit

def find_keywords(keywords: Iterable[bytes], data: bytes) -> List[Hit]:
    data = data.lower()
    return [
        Hit(keyword, start, start+len(keyword))
        for keyword in keywords
        for start in find_all(keyword, data)
    ]

def find_all(keyword: bytes, data:bytes) -> List[int]:
    starts = []
    start = data.find(keyword)
    while start >= 0:
        starts.append(start)
        start = data.find(keyword, start+len(keyword))
    return starts