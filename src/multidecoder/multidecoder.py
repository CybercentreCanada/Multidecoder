from __future__ import annotations

from multidecoder.node import Node
from multidecoder.registry import Registry, build_registry

DEFAULT_DEPTH_LIMIT = 10


class Multidecoder:
    def __init__(self, decoders: Registry | None = None) -> None:
        self.decoders = decoders if decoders else build_registry()

    def scan(self, data: bytes, depth_limit: int = DEFAULT_DEPTH_LIMIT) -> Node:
        """Search data for all possible decodings.

        A decoded result is recursively scanned unless it is the result of more scans than the depth_limit.
        Results are organized in a tree where each result's parent is the context in which it was found.
        """
        return self.scan_node(Node("", data, "", 0, len(data)), depth_limit)

    def scan_node(self, node: Node, depth_limit: int = DEFAULT_DEPTH_LIMIT) -> Node:
        """Expand a node with decodings.

        If a node has no children it's value is searched for possible decodings.
        If a node already has children, instead it's children are scanned.
        A decoded result is recursively rescanned unless it is the result of more scans than the depth_limit.
        Results are organized in a tree where each result's parent is the context in which it was found.
        """
        if depth_limit <= 0:
            return node
        if node.children:
            # Don't rescan nodes with existing children
            for child in node.children:
                self.scan_node(child, depth_limit - 1)
            return node

        stack: list[Node] = []
        decode_end = 0  # end of the last decoded context
        offset = 0  # start of the current node relative to the start of the original node

        # Get results in sorted order
        results = sorted(
            (hit for search in self.decoders for hit in search(node.value) if hit.value),
            key=lambda t: (t.start, -t.end),
        )

        for hit in results:
            # Ignore values if in a decoded context
            if hit.end <= decode_end:
                continue
            # Return to the context that contains the current hit
            while hit.end > offset + len(node.value):
                offset -= node.start
                if stack:  # Todo: Log here
                    node = stack.pop()
            hit.shift(-offset)
            # Prevent analyzer rematching its own decoded output
            if hit.start == 0 and hit.value == node.value and hit.type == node.type:
                continue
            hit.parent = node
            node.children.append(hit)

            if hit.value.lower() != hit.original.lower() or hit.children:
                # Add decoded result and check for new IOCs
                decode_end = hit.end
                self.scan_node(hit, depth_limit - 1)
            else:
                # No need to rescan, set as context
                stack.append(node)
                node = hit
                offset += hit.start

        return stack[0] if stack else node
