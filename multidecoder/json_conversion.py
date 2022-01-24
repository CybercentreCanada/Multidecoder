from __future__ import annotations

import json

from typing import Any


def tree_to_json(tree: list[dict[str, Any]], **kargs) -> str:
    return json.dumps(decode_list(tree), **kargs)

def json_to_tree(serialized: str, **kargs) -> list[dict[str,Any]]:
    return encode_list(json.loads(serialized, **kargs))

def decode_bytes(b: bytes) -> str:
    return b.decode('latin-1')

def encode_bytes(s: str) -> bytes:
    return s.encode('latin-1')

def decode_dict(d: dict[str, Any]) -> dict[str, Any]:
    for k, v in d.items():
        if isinstance(v, bytes):
            d[k] = decode_bytes(v)
        elif isinstance(v, list):
            decode_list(v)
        elif isinstance(v, dict):
            decode_dict(v)
    return d

def encode_dict(d: dict[str, Any]) -> dict[str, Any]:
    for k, v in d.items():
        if isinstance(v, str):
            d[k] = encode_bytes(v)
        elif isinstance(v, list):
            encode_list(v)
        elif isinstance(v, dict):
            encode_dict(v)
    return d

def decode_list(L: list[Any]) -> list[Any]:
    for i in range(len(L)):
        if isinstance(L[i], dict):
            decode_dict(L[i])
        elif isinstance(L[i], bytes):
            L[i] = decode_bytes(L[i])
        elif isinstance(L[i], list):
            decode_list(L[i])
    return L

def encode_list(L: list[Any]) -> list[Any]:
    for i in range(len(L)):
        if isinstance(L[i], dict):
            encode_dict(L[i])
        elif isinstance(L[i], str):
            L[i] = encode_bytes(L[i])
        elif isinstance(L[i], list):
            encode_list(L[i])
    return L
