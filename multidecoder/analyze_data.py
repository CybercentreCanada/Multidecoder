from itertools import chain
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

from multidecoder import Hit
from multidecoder.pe_file import find_pe_files
from multidecoder.base64 import find_base64
from multidecoder.network import find_domains, find_emails, find_ips, find_urls

# Type declarations
AnalyzerMap = Dict[str, Callable[[bytes], List[Hit]]]
Context = Union[Dict[str, Any], bytes]

# Analysis maps
DECODERS: AnalyzerMap = {
    'base64': find_base64
}
ANALYZERS: AnalyzerMap = {
    'PE file': find_pe_files,
    'network.domain': find_domains,
    'network.email': find_emails,
    'network.ip': find_ips,
    'network.url': find_urls
}

KEY='value'

def analyze_data(data: bytes,
                 depth: int = 10,
                 analyzers: AnalyzerMap=ANALYZERS,
                 decoders: AnalyzerMap=DECODERS,
                 _original: Optional[bytes] = None
                 ) -> Dict[str, Any]:
    """
    Report the combined analysis results.

    Args:
        data: The data to search
        depth: The depth at which to search nested decodings
        analyzers: map of labels to analysis functions
        decoders: map of labels to decoding functions
                  (analysis functions where the text is transformed and should be reanalyzed)
        _original: used in recursive calls on decoded hits to pass the undecoded data for whitelisting
                   ignore when calling externally
    Returns:
        A JSON-like (but with byte values) dictionary structure of the results found,
        with each result nested inside the context it was found in.
    """
    if depth <= 0: return {}

    results: Dict[str, List[Hit]] = {}
    for name, search in chain(analyzers.items(), decoders.items()):
        hits = search(data)[::-1]
        if hits:
            results[name] = hits

    parsed = {}
    context: Context = parsed
    label = None
    end = len(data)
    stack: List[Tuple[Context, int, Optional[str]]] = []
    while results:
        first, first_label = _pop_first(results)
        if _original and first.value in _original:
            continue
        while first.end > end:
            # We are past the end of the current context
            assert stack # Stack must have previous context or something has gone wrong
            assert label # Label is only None at bottom of stack
            if first.start < end:
                # We have an overlap
                # Not sure what to do about overlaps yet
                raise Exception(f'Overlapping hits {first} {context}')
            # Nest current context in the next down and switch to that context
            context, end, label =_pop_context(stack, context, label)
        # Now first.end <= end and so first is contained within the current context
        # Add old context to stack
        stack.append((context, end, label))
        if first_label in decoders:
            # Get new results
            decoded_results = analyze_data(first.value, depth-1, analyzers, decoders,
                                           _original=data[first.start:first.end])
            decoded_results[KEY] = first.value
            # Decoders are only the context of their decoded results
            context, end, label = _pop_context(stack, decoded_results, first_label)
        else:
            # Make first the new context
            context, end, label = first.value, first.end, first_label

    # Clean up context stack
    while stack:
        assert label
        context, end, label = _pop_context(stack, context, label)

    return parsed

def _pop_first(results: Dict[str, List])-> Tuple[Hit, str]:
    """
    Pop the hit in results that starts first in the data.
    If multiple hits start in the same position the one that ends last is popped

    Args:
        results: mapping of labels to lists of hits. In the lists the hits must be
                 non-overlapping reverse sorted by start position
    Returns:
        The first hit along with its label
    """
    label = min(results, key=lambda k: (results[k][-1].start, -results[k][-1].end))
    first = results[label].pop()
    if not results[label]:
        del results[label]
    return (first, label)

def _pop_context(stack: List[Tuple[Context, int, Optional[str]]],
                  value: Context, value_label: str,
                  )-> Tuple[Context, int, Optional[str]]:
    """
    Add value to the entry with key label of parsed.

    Entries go from not existing if no values have been added,
    to containing a single value if one value has been added,
    to containing a list of added values if more than one value has been added.

    Args:
        parsed: the dictionary to update.
        label: the key to add value under.
        value: the value to add.
    """
    c, end, label = stack.pop()
    context: Dict[str, Any] = {KEY: c} if isinstance(c, bytes) else c
    if value_label in context:
        if isinstance(context[value_label], list):
            context[value_label].append(value)
        else:
            context[value_label] = [context[value_label], value]
    else:
        context[value_label] = value
    return context, end, label