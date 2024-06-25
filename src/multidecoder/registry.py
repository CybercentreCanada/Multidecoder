"""
Module for automatically registering and collecting decoder functions
"""

from __future__ import annotations

import importlib
import inspect
import os
import pkgutil
from functools import partial
from typing import TYPE_CHECKING, Callable, Iterable, List

import multidecoder
import multidecoder.decoders
from multidecoder.keyword import find_keywords
from multidecoder.node import Node

if TYPE_CHECKING:
    from typing_extensions import TypeAlias

# Registry type
Decoder: TypeAlias = Callable[[bytes], List[Node]]
Registry: TypeAlias = List[Decoder]


def decoder(func: Decoder) -> Decoder:
    """Decorator for decoding functions"""

    func._decoder = True
    return func


def build_registry(
    directory: str = "",
    include: Iterable[str] | None = None,
    exclude: Iterable[str] | None = None,
) -> Registry:
    """Get both analyzer functions and keyword functions"""
    keywords = get_keywords(directory)
    keywords.extend(get_analyzers(include=include, exclude=exclude))
    return keywords


def get_analyzers(include: Iterable[str] | None = None, exclude: Iterable[str] | None = None) -> Registry:
    """Get all analyzers"""
    decoders: Registry = []
    include = set(include) if include else {}
    exclude = set(exclude) if exclude else {}
    for submod_info in pkgutil.iter_modules(multidecoder.decoders.__path__):
        if include and submod_info.name not in include:
            continue
        if exclude and submod_info.name in exclude:
            continue
        submodule = importlib.import_module("." + submod_info.name, package=multidecoder.decoders.__name__)
        for _, function in inspect.getmembers(submodule, inspect.isfunction):
            if hasattr(function, "_decoder"):
                decoders.append(function)
    return decoders


def get_keywords(directory: str = "") -> Registry:
    """Get keyword search functions from a directory"""
    directory = directory or os.path.join(next(iter(multidecoder.__path__)), "keywords")
    keyword_map: Registry = []
    for subdir, _, files in os.walk(directory):
        for file_name in files:
            with open(os.path.join(subdir, file_name), "rb") as keyword_file:
                keywords = set(keyword_file.read().splitlines())
                keywords.discard(b"")
            if not keywords:
                continue
            keyword_map.append(partial(find_keywords, file_name, keywords))
    return keyword_map
