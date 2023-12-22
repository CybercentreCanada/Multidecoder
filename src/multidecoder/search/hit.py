"""
Hit class for search results
"""
from __future__ import annotations

from dataclasses import dataclass

import regex as re


@dataclass
class Hit:
    type: str
    start: int
    end: int
    children: list[Hit]

    @classmethod
    def from_match(cls, label: str, match: re.Match[bytes], group: int = 0) -> Hit:
        return cls(label, *match.span(group), [])

    @property
    def span(self) -> tuple[int, int]:
        return self.start, self.end
