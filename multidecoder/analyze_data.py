
from typing import Dict, List

from multidecoder.pe_file import find_pe_files
from multidecoder.base64 import base64_search

DECODERS = {
    'base64':
}
ANALYZERS = {
    'PE files': find_pe_files
}

def analyze_data(data: bytes, depth=10) -> Dict[str, List]:
    """
    Report the combined analysis results.
    """
    results = {}
    for name, analyzer in ANALYZERS.items():
        results[name] = analyzer(data)
    for name, decoder in DECODERS.items():
        if depth > 0:
            results[name] = [analyze_data(hit.value, depth=depth-1).update(hit._asdict()) for hit in decoder(data)]
        else:
            results[name] = decoder(data)

    return results
