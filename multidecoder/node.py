from __future__ import annotations

from typing import Iterable, Iterator, Optional


class Node():
    def __init__(self,
                 type: str,
                 value: bytes,
                 obfuscation: list[str],
                 start: int = 0,
                 end: int = 0,
                 parent: Optional[Node] = None,
                 children: Optional[list[Node]] = None):
        self.type = type
        self.value = value
        self.obfuscation = obfuscation
        self.start = start
        self.end = end
        self.children: list[Node] = children if children else []
        self.parent = parent

    def __repr__(self) -> str:
        return f'Node({self.type}, {self.value!r}, {self.obfuscation}, {self.start}, {self.end})'

    def __eq__(self, other):
        # Ignoring parent in eq to allow unit tests to not construct backreferences
        # and to avoid potential infinite loop problems
        return (isinstance(other, Node) and self.type == other.type
                and self.value == other.value
                and self.obfuscation == other.obfuscation
                and self.start == other.start
                and self.end == other.end
                and self.children == other.children)

    def __iter__(self) -> Iterator[Node]:
        """Depth first iteration over the entire tree of children of the node, starting with the node itself.

        If only the direct children are wanted iterating over node.children can be used instead"""
        def node_generator(node: Node) -> Iterable[Node]:
            yield node
            for child in node.children:
                for subchild in node_generator(child):
                    yield subchild
        return iter(node_generator(self))
