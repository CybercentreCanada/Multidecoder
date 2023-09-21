from __future__ import annotations

import json
from typing import Any

from multidecoder.node import Node


def node_to_dict(node: Node) -> dict[str, Any]:
    return {
        "type": node.type,
        "value": node.value.hex(),
        "obfuscation": node.obfuscation,
        "start": node.start,
        "end": node.end,
        # Ignore parent to avoid circularity
        "children": [node_to_dict(child) for child in node.children],
    }


class NodeEncoder(json.JSONEncoder):
    def default(self, node):
        if isinstance(node, Node):
            return node_to_dict(node)
        return json.JSONEncoder.default(self, node)


def as_node(d: dict[str, Any], parent: Node | None = None) -> Node:
    node = Node(
        type_=d["type"],
        value=bytes.fromhex(d["value"]),
        obfuscation=d["obfuscation"],
        start=d["start"],
        end=d["end"],
        parent=parent,
    )
    node.children = [as_node(child, node) for child in d["children"]]
    return node


def tree_to_json(tree: Node, **kargs) -> str:
    return json.dumps(tree, cls=NodeEncoder, **kargs)


def json_to_tree(serialized: str, **kargs) -> Node:
    return json.loads(serialized, default=as_node, **kargs)
