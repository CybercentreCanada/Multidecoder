from __future__ import annotations

from itertools import chain
from typing import Any, Optional

from multidecoder.hit import Hit
from multidecoder.registry import AnalyzerMap, get_analyzers

class MultiDecoder:
    def __init__(self, detectors: Optional[AnalyzerMap] = None, decoders: Optional[AnalyzerMap] = None) -> None:
        if detectors or decoders:
            self.detectors = detectors or {}
            self.decoders = decoders or {}
        else:
            detectors, decoders = get_analyzers()
            self.detectors = detectors
            self.decoders = decoders

    def scan(self, data: bytes, depth: int = 10, _original: bytes = b'') -> list[dict[str, Any]]:
        """
        Report the combined analysis results.

        Args:
            data: The data to search
            depth: The depth at which to search nested decodings
            _original: used in recursive calls on decoded hits to pass the undecoded data for whitelisting
                    ignore when calling externally
        Returns:
            A JSON-like (but with byte values) dictionary structure of the results found,
            with each result nested inside the context it was found in.
        """
        if depth <= 0: return []

        children = []
        end = len(data)
        stack = []

        # Get results in sorted order
        for label, hit in sorted(
                ((label, hit) for label, search in chain(self.detectors.items(), self.decoders.items())
                for hit in search(data) if hit.value not in _original),
                key=lambda t: (t[1].start, -t[1].end)):
            child = {
                'type': label,
                'value': hit.value,
                'children': []
            }
            # Return to the context that contains the current hit
            while end < hit.end:
                children, end = stack.pop()

            # Add it to the parents list of children
            children.append(child)

            if label in self.decoders:
                # Children of decoded hits are results on the decoded data
                child['raw'] = data[hit.start:hit.end]
                child['children'] = self.scan(child['value'], depth-1, child['raw'])
            else:
                # Set the current result as the context
                stack.append((children, end))
                children, end = child['children'], hit.end

        return stack[0][0] if stack else children
