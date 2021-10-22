from __future__ import annotations

import inspect
import importlib
import os
import pkgutil

from typing import Callable, Iterable, Optional

import multidecoder.analyzers
from multidecoder.hit import Hit
from multidecoder.keyword import find_keywords

# Registry type
AnalyzerMap = dict[str, Callable[[bytes], list[Hit]]]

# Decorator to mark functions to load
def analyzer(label: str):
    def decorator(f):
        f.label = label
        return f
    return decorator

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
                  exclude: Optional[Iterable[str]]=None) -> AnalyzerMap:
    analyzers = {}
    for submod_info in pkgutil.iter_modules(multidecoder.analyzers.__path__):
        if include and submod_info.name not in include:
            continue
        if exclude and submod_info.name in exclude:
            continue
        submodule = importlib.import_module('.'+submod_info.name, package=multidecoder.analyzers.__name__)
        for _, function in inspect.getmembers(submodule, inspect.isfunction):
            if hasattr(function, 'label'):
                analyzers[function.label] = function
    return analyzers