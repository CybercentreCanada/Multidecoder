from __future__ import annotations

import argparse
import os
import sys

from multidecoder._version import version
from multidecoder.multidecoder import Multidecoder
from multidecoder.json_conversion import tree_to_json
from multidecoder.query import string_summary, squash_replace
from multidecoder.registry import build_map


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('filepath', nargs='?', metavar='FILE')
    parser.add_argument('--version', '-V', action='version', version="%(prog)s " + version)
    parser.add_argument('--keywords', '-k')
    output_format = parser.add_mutually_exclusive_group()
    output_format.add_argument('--json', '-j', action='store_true')
    output_format.add_argument('--replace', '-r', action='store_true')
    args = parser.parse_args()
    if args.filepath:
        try:
            with open(args.filepath, 'rb') as f:
                data = f.read()
        except Exception as e:
            print(e, file=sys.stderr)
            return
    else:
        data = sys.stdin.buffer.read()
    if args.keywords:
        if not os.path.isdir(args.keywords):
            print('--keywords argument must be a directory', file=sys.stderr)
            return
        analyzers = build_map(args.keywords)
    else:
        analyzers = None
    md = Multidecoder(analyzers)
    tree = md.scan(data)
    if args.json:
        print(tree_to_json(tree))
    elif args.replace:
        sys.stdout.buffer.write(squash_replace(data, tree))
    else:
        for string in string_summary(tree):
            print(string)


if __name__ == '__main__':
    main()
