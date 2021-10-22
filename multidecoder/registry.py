from __future__ import annotations

import inspect
import importlib
import os
import pkgutil

from functools import partial
from typing import Callable, Iterable, Optional

import multidecoder.analyzers
from multidecoder.hit import Hit
from multidecoder.keyword import find_keywords

# Type declarations
AnalyzerMap = dict[str, Callable[[bytes], list[Hit]]]

# Decorator to mark functions to load
def _search_decorator(decodes: bool, label: str):
    def decorator(f):
        f.label = label
        f.decodes = decodes
        return f
    return decorator

# Sugar to make decorators more legible
detector = partial(_search_decorator, False)
decoder = partial(_search_decorator, True)

def get_keywords(directory: str) -> dict[str, Callable[[bytes], list[Hit]]]:
    keyword_map = {}
    for subdir, _, files in os.walk(directory):
        for file_name in files:
            with open(file_name, 'rb') as f:
                keywords = f.readlines()
            if not keywords:
                continue
            label = subdir.replace(os.sep, '.') + file_name
            if keywords[0].startswith(b'#'):
                if len(keywords) == 1:
                    continue
                ignore_case = keywords[0][1:].strip().lower() == b'nocase'
                keyword_map[label] = lambda data: find_keywords(keywords[1:],
                                                                data.lower() if ignore_case else data)
            else:
                keyword_map[label] = lambda data: find_keywords(keywords, data)
    return keyword_map

def get_analyzers(include: Optional[Iterable[str]]=None,
                  exclude: Optional[Iterable[str]]=None) -> tuple[AnalyzerMap, AnalyzerMap]:
    detectors = {}
    decoders = {}
    for submod_info in pkgutil.iter_modules(multidecoder.analyzers.__path__):
        if include and submod_info.name not in include:
            continue
        if exclude and submod_info.name in exclude:
            continue
        submodule = importlib.import_module('.'+submod_info.name, package=multidecoder.analyzers.__name__)
        for _, function in inspect.getmembers(submodule, inspect.isfunction):
            if hasattr(function, 'label') and hasattr(function, 'decodes'):
                (decoders if function.decodes else detectors)[function.label] = function
    return (detectors, decoders)