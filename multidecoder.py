"""
MultiDecoder
"""


import binascii
import re


def base64_search(text):
    """
    Finds all base64 in text
    retuns a list of decoded sections
    """
    b64_matches = set()
    base64_results = []
    base64_pattern = b'([\x20]{0,2}(?:[A-Za-z0-9+/]{10,}={0,2}(?:&#[x1][A0];)?[\r]?[\n]?){2,})'
    for b64_match in re.findall(base64_pattern, text):
        b64_string = b64_match.replace(b'\n', b'').replace(b'\r', b'').replace(b' ', b'')\
                .replace(b'&#xA;', b'').replace(b'&#10;', b'')
        if b64_string in b64_matches:
            continue
        b64_matches.add(b64_string)
        uniq_char = set(b64_string)
        if len(uniq_char) > 6:
            b64result = binascii.a2b_base64(b64_string)
            if b64result:
                base64_results.append(b64result)
    return base64_results
