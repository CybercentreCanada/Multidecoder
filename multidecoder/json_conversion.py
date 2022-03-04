from __future__ import annotations

import simplejson

from typing import Any


def tree_to_json(tree: list[dict[str, Any]], **kargs) -> str:
    return simplejson.dumps(tree, encoding='latin-1', **kargs)


def json_to_tree(serialized: str, **kargs) -> list[dict[str, Any]]:
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
    if 'start' not in d:
        raise ValueError('Invalid object, entry missing start')
    if not isinstance(d['start'], int):
        raise ValueError(f'Invalid object, start must be int but got {type(d["start"])}')
    if 'end' not in d:
        raise ValueError('Invalid object, entry missing end')
    if not isinstance(d['end'], int):
        raise ValueError(f'Invalid object, end must be int but got {type(d["start"])}')
    if 'obfuscation' in d:
        if not isinstance(d['obfuscation'], str):
            raise ValueError(f'Invalid object, obfuscation must be str but got {type(d["obfuscation"])}')
    else:
        d['obfuscation'] = ''
    if 'children' in d:
        check_list(d['children'])
    else:
        d['children'] = []
    return d
