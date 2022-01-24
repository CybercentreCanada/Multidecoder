from __future__ import annotations

import argparse
import sys

from multidecoder import MultiDecoder, __version__
from multidecoder.json_conversion import tree_to_json

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('filepath', nargs='?', metavar='FILE')
    parser.add_argument('--version', '-V', action='version', version="%(prog)s " + __version__)
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
    print(tree_to_json(md.scan(data), indent=4))

if __name__ == '__main__':
    main()