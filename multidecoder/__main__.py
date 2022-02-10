from __future__ import annotations

import argparse
import sys

from multidecoder import MultiDecoder, __version__
from multidecoder.json_conversion import tree_to_json
from multidecoder.query import decoded_network, mixed_case, successful_decodings

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('filepath', nargs='?', metavar='FILE')
    parser.add_argument('--version', '-V', action='version', version="%(prog)s " + __version__)
    parser.add_argument('--json', '-j', action='store_true')
    args = parser.parse_args()
    if args.filepath:
        try:
            with open(args.filepath, 'rb') as f:
                data = f.read()
        except Exception as e:
            print(e)
            return
    else:
        data = sys.stdin.buffer.read()
    md = MultiDecoder()
    tree = md.scan(data)
    if args.json:
        print(tree_to_json(tree, indent=4))
    print('-- Successful Decodings --')
    successful_decodings(tree)
    print('-- Decoded Network Indicators --')
    decoded_network(tree, [])
    print('-- Mixed Case Detection --')
    mixed_case(tree)

if __name__ == '__main__':
    main()