from __future__ import annotations

from typing import Optional

from multidecoder.node import Node
from multidecoder.registry import Registry, build_registry

DEFAULT_DEPTH = 10


class Multidecoder:
    def __init__(self, decoders: Optional[Registry] = None) -> None:
        self.decoders = decoders if decoders else build_registry()

    def scan(self, data: bytes, depth: int = DEFAULT_DEPTH) -> Node:
        return self.scan_node(Node("", data, "", 0, len(data)), depth)

    def scan_node(self, node: Node, depth: int = DEFAULT_DEPTH) -> Node:
        """
        Report the combined analysis results.

        Args:
            data: The data to search
            depth: The depth at which to search nested decodings
        Returns:
            A JSON-like (but with byte values) dictionary structure of the results found,
            with each result nested inside the context it was found in.
        """
        if depth <= 0:
            return node
        if node.children:
            # Don't rescan nodes with existing children
            for child in node.children:
                self.scan_node(child, depth - 1)
            return node

        stack: list[Node] = []
        decode_end = 0  # end of the last decoded context
        offset = (
            0  # start of the current node relative to the start of the original node
        )

        # Get results in sorted order
        results = sorted(
            (
                hit
                for search in self.decoders
                for hit in search(node.value)
                if hit.value
            ),
            key=lambda t: (t.start, -t.end),
        )

        for hit in results:
            # Ignore values if in a decoded context
            if hit.end <= decode_end:
                continue
            # Return to the context that contains the current hit
            while hit.end > offset + len(node.value):
                offset -= node.start
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
                self.scan_node(hit, depth - 1)
            else:
                # No need to rescan, set as context
                stack.append(node)
                node = hit
                offset += hit.start

        return stack[0] if stack else node
