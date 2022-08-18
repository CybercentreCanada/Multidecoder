from __future__ import annotations

from collections import Counter
from typing import Optional

from multidecoder.node import Node


def invert_tree(tree: list[Node]) -> list[Node]:
    def invert_helper(tree: list[Node], parent: Optional[Node]) -> list[Node]:
        nodes = []
        for node in tree:
            node.parent = parent
            nodes.append(node)
            nodes.extend(invert_helper(node.children, node))
        return nodes
    return invert_helper(tree, None)


def make_label(node: Optional[Node]) -> str:
    label_list = []
    value = node.value if node else b''
    while node:
        if node.type:
            label_list.append(node.type)
        if node.obfuscation:
            label_list.append('>'+'/>'.join(node.obfuscation))
        node = node.parent
    return '/'.join(label_list[::-1]) + ' ' + repr(value)[2:-1]


def string_summary(tree: list[Node]) -> list[str]:
    return [
        make_label(node) for node in invert_tree(tree)
    ]


def squash_replace(data: bytes, tree: list[Node]) -> bytes:
    offset = 0
    output = []
    for node in tree:
        node_data = squash_replace(node.value, node.children)
        if node_data != data[node.start:node.end]:
            output.append(data[offset:node.start])
            if node.type.endswith('string'):
                node_data = b'"' + node_data + b'"'
            output.append(node_data)
            offset = node.end
    output.append(data[offset:])
    return b''.join(output)


def obfuscation_counts(tree: list[Node]) -> Counter[str]:
    counts: Counter[str] = Counter()
    for node in tree:
        if node.obfuscation:
            counts.update(node.obfuscation)
        counts.update(obfuscation_counts(node.children))
    return counts
