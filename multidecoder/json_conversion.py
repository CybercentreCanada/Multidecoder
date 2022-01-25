from __future__ import annotations

import simplejson

from typing import Any

def tree_to_json(tree: list[dict[str, Any]], **kargs) -> str:
    return simplejson.dumps(tree, encoding='latin-1', **kargs)

def json_to_tree(serialized: str, **kargs) -> list[dict[str,Any]]:
    return check_list(simplejson.loads(serialized, encoding='latin-1', **kargs))

def check_list(L: Any) -> list[dict[str, Any]]:
    if not isinstance(L, list):
        raise ValueError(f'Invalid object, Expected a list but got {type(L)}.')
    for entry in L:
        check_dict(entry)
    return L

def check_dict(d: Any) -> dict[str, Any]:
    if not isinstance(d, dict):
        raise ValueError(f'Invalid object, entry must be dict but got {type(d)}')
    if 'type' not in d:
        raise ValueError('Invalid object, entry missing type')
    if not isinstance(d['type'], str):
        raise ValueError(f'Invalid object, entry type must be str but got {type(d["type"])}')
    if 'value' not in d:
        raise ValueError('Invalid object, entry missing value')
    if not isinstance(d['value'], str):
        raise ValueError(f'Invalid object, entry value must be str but got {type(d["value"])}')
    d['value'] = d['value'].encode('latin-1')
    if 'children' in d:
        check_list(d['children'])
    else:
        d['children'] = []
    if 'decoded' in d:
        if not isinstance(d['decoded'], str):
            raise ValueError(f'Invalid object, entry decoded must be str but got {type(d["decoded"])}')
        d['decoded'] = d['decoded'].encode('latin-1')
        if 'decoded_children' in d:
            check_list(d['decoded_children'])
        else:
            d['decoded_children'] = []
    elif 'decoded_children' in d:
        raise ValueError('Invalid object, entry has decoded children but no decoded')
    return d