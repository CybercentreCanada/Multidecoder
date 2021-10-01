from __future__ import annotations

import os

from functools import partial
from typing import Callable

from multidecoder.hit import Hit
from multidecoder.keyword import find_keywords

# Decorator to mark functions to load
def search_decorator(decodes: bool, label: str):
    def decorator(f):
        f.label = label
        f.decodes = decodes
        return f
    return decorator

# Sugar to make decorators legible
detector = partial(search_decorator, False)
decoder = partial(search_decorator, True)

def get_keywords(directory: str) -> dict[str, Callable[[bytes], list[Hit]]]:
    keyword_map = {}
    for subdir, _, files in os.walk(directory):
        for file_name in files:
            with open(file_name, 'rb') as f:
                keywords = f.readlines()
            label = subdir.replace(os.sep, '.') + file_name
            if keywords:
                if keywords[0].startswith(b'#') and len(keywords) > 1:
                    ignore_case = keywords[0][1:].strip().lower() == b'nocase'
                    keyword_map[label] = lambda data: find_keywords(keywords[1:],
                                                                data.lower() if ignore_case else data)
                else:
                    keyword_map[label] = lambda data: find_keywords(keywords, data)
    return keyword_map

def get_decoders():
    pass

def get_detectors():
    pass