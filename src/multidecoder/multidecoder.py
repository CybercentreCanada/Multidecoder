from __future__ import annotations

from typing import Optional

from multidecoder.node import Node
from multidecoder.registry import AnalyzerMap, build_map


class Multidecoder:
    def __init__(self, analyzers: Optional[AnalyzerMap] = None) -> None:
        self.analyzers = analyzers if analyzers else build_map()

    def scan(self, data: bytes) -> Node:
        return self.scan_node(Node("", data, [], 0, len(data)))

    def scan_node(self, node: Node, depth: int = 10) -> Node:
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

        stack: list[Node] = []
        decode_end = 0  # end of the last decoded context
        offset = (
            0  # start of the current node relative to the start of the original node
        )

        # Get results in sorted order
        results = sorted(
            (
                (label, hit)
                for search, label in self.analyzers.items()
                for hit in search(node.value)
                if hit.value
            ),
            key=lambda t: (t[1].start, -t[1].end),
        )

        for label, hit in results:
            # Ignore values if in a decoded context
            if hit.end <= decode_end:
                continue
            # Return to the context that contains the current hit
            while offset + len(node.value) < hit.end:
                offset -= node.start
                node = stack.pop()
            # Create the child structure
            child = Node(
                type=label,
                value=hit.value,
                obfuscation=hit.obfuscation,
                start=hit.start - offset,
                end=hit.end - offset,
                parent=node,
            )
            node.children.append(child)

            if hit.value.lower() != node.value[hit.start : hit.end].lower():
                # Add decoded result and check for new IOCs
                decode_end = hit.end
                child = self.scan_node(child, depth - 1)
                # Prevent analyzer rematching its own decoded output
                if (
                    len(child.children) == 1
                    and child.children[0].value == hit.value
                    and child.children[0].type == label
                ):
                    child.children = child.children[0].children
            else:
                # No need to rescan, set as context
                stack.append(node)
                node, offset = child, hit.start

        return stack[0] if stack else node
