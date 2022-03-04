from __future__ import annotations

from typing import Any


def make_label(stack, value) -> str:
    label_list = []
    for node in stack:
        if node['obfuscation']:
            label_list.append('>'+node['obfuscation'])
        if node['type']:
            label_list.append(node['type'])
    return '/'.join(label_list)


def string_summary(tree: list[dict[str, Any]], stack=None) -> None:
    if stack is None:
        stack = []
    for node in tree:
        stack.append(node)
        print(make_label(stack, node['value']), node['value'])
        if 'children' in node and node['children']:
            string_summary(node['children'], stack)
        stack.pop()
