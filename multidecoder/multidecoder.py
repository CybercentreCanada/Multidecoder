from itertools import chain
from multidecoder.shell import find_shell_strings
from typing import Any, Callable, Dict, List

from multidecoder.hit import Hit
from multidecoder.base64 import find_base64
from multidecoder.network import find_domains, find_emails, find_ips, find_urls
from multidecoder.pe_file import find_pe_files
from multidecoder.shell import find_shell_strings

# Type declarations
AnalyzerMap = Dict[str, Callable[[bytes], List[Hit]]]

# Analysis maps
DECODERS: AnalyzerMap = {
    'base64': find_base64
}
ANALYZERS: AnalyzerMap = {
    'PE file': find_pe_files,
    'network.domain': find_domains,
    'network.email': find_emails,
    'network.ip': find_ips,
    'network.url': find_urls,
    'shell strings': find_shell_strings
}

class MultiDecoder:
    def __init__(self, analyzers: AnalyzerMap = ANALYZERS, decoders: AnalyzerMap = DECODERS) -> None:
        self.analyzers = analyzers
        self.decoders = decoders

    def scan(self, data: bytes, depth: int = 10, _original: bytes = b'') -> List[Dict[str, Any]]:
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
                ((label, hit) for label, search in chain(self.analyzers.items(), self.decoders.items())
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
