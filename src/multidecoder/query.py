from __future__ import annotations

from collections import Counter
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from multidecoder.node import Node


def invert_tree(tree: list[Node]) -> list[Node]:
    nodes: list[Node] = []
    for node in tree:
        nodes.extend(node)
    return nodes


def make_label(node: Node | None) -> str:
    label_list = []
    while node:
        if node.type:
            label_list.append(node.type)
        if node.obfuscation:
            label_list.append(">" + node.obfuscation)
        node = node.parent
    return "/".join(label_list[::-1])


def string_summary(tree: Node) -> list[str]:
    return [make_label(node) + " " + repr(node.value)[2:-1] for node in tree]


def squash_replace(data: bytes, tree: list[Node]) -> bytes:
    offset = 0
    output = []
    for node in tree:
        node_data = squash_replace(node.value, node.children)
        if node_data != data[node.start : node.end]:
            output.append(data[offset : node.start])
            if node.type.endswith("string"):
                node_data = b'"' + node_data + b'"'
            output.append(node_data)
            offset = node.end
    output.append(data[offset:])
    return b"".join(output)


def obfuscation_counts(tree: list[Node]) -> Counter[str]:
    counts: Counter[str] = Counter()
    for node in tree:
        if node.obfuscation:
            counts.update(node.obfuscation)
        counts.update(obfuscation_counts(node.children))
    return counts
