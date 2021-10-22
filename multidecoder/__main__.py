from __future__ import annotations
import argparse
import json
import sys

from typing import Any

from multidecoder import MultiDecoder

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('filepath', nargs='?', metavar='FILE')
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
    print(json.dumps(decode_list(md.scan(data)), indent=4))

def decode_dict(d: dict[str, Any]) -> dict[str, Any]:
    for k, v in d.items():
        if isinstance(v, bytes):
            d[k] = decode_bytes(v)
        elif isinstance(v, list):
            decode_list(v)
        elif isinstance(v, dict):
            decode_dict(v)
    return d

def decode_list(L: list[Any]) -> list[Any]:
    for i in range(len(L)):
        if isinstance(L[i], dict):
            decode_dict(L[i])
        elif isinstance(L[i], bytes):
            L[i] = decode_bytes(L[i])
        elif isinstance(L[i], list):
            decode_list(L[i])
    return L

def decode_bytes(b: bytes) -> str:
    try:
        string = b.decode()
    except UnicodeDecodeError:
        string = b.hex()
    return string

if __name__ == '__main__':
    main()