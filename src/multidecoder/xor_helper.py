"""Helper functions for xor capabilities."""

import regex as re

from multidecoder.node import Node

# Supported by https://github.com/CYB3RMX/Qu1cksc0pe/blob/1a349826b248e578b0a2ec8b152eeeddf059c388/Modules/powershell_analyzer.py#L116
XOR_RE = rb"(?i)-b?xor\s*(\d{1,3})"


def get_xorkey(data: bytes) -> int:
    xorkey = re.search(XOR_RE, data)
    if xorkey:
        return int(xorkey.group(1))
    return None


def apply_xor_key(xorkey: int, data: bytes, node: Node, new_node_type: str) -> Node:
    data = bytes(b ^ xorkey for b in data)
    node.children.append(
        Node(
            new_node_type,
            data,
            "cipher.xor" + str(xorkey),
            end=len(data),
            parent=node,
        )
    )
    return node
