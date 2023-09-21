from __future__ import annotations

from typing import Iterator


class Node:
    __slots__ = "type", "value", "obfuscation", "start", "end", "parent", "children"

    def __init__(
        self,
        type_: str,
        value: bytes,
        obfuscation: str = "",
        start: int = 0,
        end: int = 0,
        parent: Node | None = None,
        children: list[Node] | None = None,
    ):
        self.type = type_
        self.value = value
        self.obfuscation = obfuscation
        self.start = start
        self.end = end
        self.parent = parent
        if children:
            self.children = children
            for child in children:
                child.parent = self
        else:
            self.children = []

    @property
    def original(self) -> bytes:
        # Value before decoding
        if self.parent:
            return self.parent.value[self.start : self.end]
        return self.value

    def shift(self: Node, offset: int) -> Node:
        """Shift the start and end value of a node by and offset

        The node is modified in place.

        Args:
            node: The node to be shifted.
            offset: The ammount to shift.

        Returns:
            The modified node.
        """
        self.start += offset
        self.end += offset
        return self

    def __repr__(self) -> str:
        return (
            f"Node({self.type!r}, {self.value!r}, {self.obfuscation!r}, "
            f"{self.start!r}, {self.end!r}, ..., {self.children!r})"
        )

    def __eq__(self, other: object) -> bool:
        # Ignoring parent in eq to allow unit tests to not construct backreferences
        # and to avoid potential infinite loop problems
        return (
            isinstance(other, Node)
            and self.type == other.type
            and self.value == other.value
            and self.obfuscation == other.obfuscation
            and self.start == other.start
            and self.end == other.end
            and self.children == other.children
        )

    def __iter__(self) -> Iterator[Node]:
        """Iterates over all the children in the tree below the node.

        The nodes appear in depth-first pre-order, and the root node is not included.
        If only the direct children are wanted iterating over node.children can be used instead.
        """

        def node_generator(node: Node) -> Iterator[Node]:
            for child in node.children:
                yield child
                yield from node_generator(child)

        return node_generator(self)


def shift_nodes(nodes: list[Node], offset: int) -> list[Node]:
    """Shift the start and end values of a list of nodes

    The list is modified in place.

    Args:
        nodes: The list of nodes
        offset: the ammount to shift

    Returns:
        The list of modified nodes.
    """
    for node in nodes:
        node.start += offset
        node.end += offset
    return nodes
