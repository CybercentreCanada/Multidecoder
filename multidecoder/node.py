from __future__ import annotations

from typing import Optional


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

    def __eq__(self, other):
        # Ignoring parent in eq to allow unit tests to not construct backreferences
        # and to avoid potential infinite loop problems
        return (isinstance(other, Node) and self.type == other.type
                and self.value == other.value
                and self.obfuscation == other.obfuscation
                and self.start == other.start
                and self.end == other.end
                and self.children == other.children)
