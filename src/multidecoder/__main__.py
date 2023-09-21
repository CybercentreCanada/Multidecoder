from __future__ import annotations

import argparse
import os
import sys

from multidecoder._version import version
from multidecoder.json_conversion import tree_to_json
from multidecoder.multidecoder import Multidecoder
from multidecoder.query import squash_replace, string_summary
from multidecoder.registry import build_registry


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("filepath", nargs="?", metavar="FILE")
    parser.add_argument("--version", "-V", action="version", version="%(prog)s " + version)
    parser.add_argument("--keywords", "-k")
    output_format = parser.add_mutually_exclusive_group()
    output_format.add_argument("--json", "-j", action="store_true")
    output_format.add_argument("--replace", "-r", action="store_true")
    args = parser.parse_args()
    if args.filepath:
        try:
            with open(args.filepath, "rb") as f:
                data = f.read()
        except Exception as e:
            print(e, file=sys.stderr)
            return
    else:
        data = sys.stdin.buffer.read()
    if args.keywords:
        if not os.path.isdir(args.keywords):
            print("--keywords argument must be a directory", file=sys.stderr)
            return
        decoders = build_registry(args.keywords)
    else:
        decoders = None
    md = Multidecoder(decoders)
    tree = md.scan(data)
    if args.json:
        print(tree_to_json(tree))
    elif args.replace:
        sys.stdout.buffer.write(squash_replace(data, tree.children))
    else:
        for string in string_summary(tree):
            print(string)


if __name__ == "__main__":
    main()
