import inspect
import importlib
import os
import pkgutil

from functools import partial
from typing import Callable, Dict, Iterable, List, Optional

import multidecoder
import multidecoder.analyzers
from multidecoder.hit import Hit
from multidecoder.keyword import find_keywords

# Registry type
AnalyzerMap = Dict[Callable[[bytes], List[Hit]], str]


def analyzer(label: str):
    """ Decorator for analysis functions """
    def decorator(f):
        f.label = label
        return f
    return decorator


def build_map(directory: str = '',
              include: Optional[Iterable[str]] = None,
              exclude: Optional[Iterable[str]] = None) -> AnalyzerMap:
    """ Get both analyzer functions and keyword functions """
    keywords = get_keywords(directory)
    keywords.update(get_analyzers(include=include, exclude=exclude))
    return keywords


def get_analyzers(include: Optional[Iterable[str]] = None,
                  exclude: Optional[Iterable[str]] = None) -> AnalyzerMap:
    """ Get all analyzers """
    analyzers = {}
    include = set(include) if include else {}
    exclude = set(exclude) if exclude else {}
    for submod_info in pkgutil.iter_modules(multidecoder.analyzers.__path__):
        if include and submod_info.name not in include:
            continue
        if exclude and submod_info.name in exclude:
            continue
        submodule = importlib.import_module('.'+submod_info.name, package=multidecoder.analyzers.__name__)
        for _, function in inspect.getmembers(submodule, inspect.isfunction):
            if hasattr(function, 'label'):
                analyzers[function] = function.label
    return analyzers


def get_keywords(directory: str = '') -> AnalyzerMap:
    """ Get keyword search functions from a directory """
    directory = directory or os.path.join(next(iter(multidecoder.__path__)), 'keywords')
    keyword_map = {}
    for subdir, _, files in os.walk(directory):
        for file_name in files:
            with open(os.path.join(subdir, file_name), 'rb') as f:
                keywords = set(f.read().splitlines())
                keywords.discard(b'')
            if not keywords:
                continue
            keyword_map[partial(find_keywords, keywords)] = file_name
    return keyword_map
