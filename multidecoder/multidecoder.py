from __future__ import annotations

from typing import Any, Optional

from multidecoder.registry import AnalyzerMap, build_map

class MultiDecoder:
    def __init__(self, analyzers: Optional[AnalyzerMap] = None) -> None:
        self.analyzers = analyzers if analyzers else build_map()

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
                ((label, hit) for label, search in self.analyzers.items()
                for hit in search(data) if hit.value not in _original),
                key=lambda t: (t[1].start, -t[1].end)):
            child = {
                'type': label,
                'value': data[hit.start:hit.end],
                'children': [],
            }
            # Return to the context that contains the current hit
            while end < hit.end:
                children, end = stack.pop()

            # Add it to the parents list of children
            children.append(child)

            if child['value'] != hit.value:
                # Add decoded result and check for new IOCs
                child['decoded'] = hit.value
                if child['value'].lower() != hit.value.lower():
                    child['decoded_children'] = self.scan(child['decoded'], depth-1, child['value'])
            # Set the current result as the context
            stack.append((children, end))
            children, end = child['children'], hit.end

        return stack[0][0] if stack else children
