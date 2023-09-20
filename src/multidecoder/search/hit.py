"""
Hit class for search results
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Hit:
    type: str
    start: int
    end: int
    children: list[Hit]

    @property
    def span(self) -> tuple[int, int]:
        return self.start, self.end
