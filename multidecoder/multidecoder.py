from __future__ import annotations

from typing import Any, Optional

from multidecoder.registry import AnalyzerMap, build_map

class MultiDecoder:
    def __init__(self, analyzers: Optional[AnalyzerMap] = None) -> None:
        self.analyzers = analyzers if analyzers else build_map()

    def scan(self, data: bytes, depth: int=10, context_type: str='') -> list[dict[str,Any]]:
        """
        Report the combined analysis results.

        Args:
            data: The data to search
            depth: The depth at which to search nested decodings
        Returns:
            A JSON-like (but with byte values) dictionary structure of the results found,
            with each result nested inside the context it was found in.
        """
        if depth <= 0: return []

        children = []
        decode_end = 0

        stack: list[tuple[list, int, int]] = []
        start, end = 0, len(data)

        # Get results in sorted order
        results = sorted(
            ((label, hit) for search, label in self.analyzers.items()
            for hit in search(data) if hit.value),
            key=lambda t: (t[1].start, -t[1].end))
        # Prevent analyzer rematching its own decoded output
        if results and results[0][0] == context_type and (results[0][1].start, results[0][1].end) == (start, end):
            results = results[1:]

        for label, hit in results:
            # Ignore values if in a decoded context
            if hit.end <= decode_end:
                continue
            # Return to the context that contains the current hit
            while end < hit.end:
                children, start, end = stack.pop()
            # Create the child structure
            child = {
                'obfuscation': hit.obfuscation,
                'type': label,
                'value': hit.value,
                'start': hit.start-start,
                'end': hit.end-start,
                'children': [],
            }
            # Add it to the parent's list of children
            children.append(child)

            if hit.value.lower() != data[hit.start:hit.end].lower():
                # Add decoded result and check for new IOCs
                decode_end = hit.end
                child['children'] = self.scan(hit.value, depth-1, context_type=label)
            else:
                # No need to rescan, set as context
                stack.append((children, start, end))
                children, start, end = child['children'], hit.start, hit.end

        return stack[0][0] if stack else children
