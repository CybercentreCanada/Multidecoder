from __future__ import annotations

from typing import Any
from xml.etree.ElementTree import TreeBuilder

def successful_decodings(tree: list[dict[str, Any]]) -> None:
    for node in tree:
        if 'children' in node and node['children']:
            successful_decodings(node['children'])
        if 'decoded_children' in node and node['decoded_children']:
            print(node['type'], node['value'], node['decoded'])
            print('')
            successful_decodings(node['children'])

def decoded_network(tree: list[dict[str,Any]], decoded_labels: list[str]) -> None:
    for node in tree:
        if node['type'].startswith('network') and decoded_labels:
            print('/'.join(decoded_labels) + '/' + node['type'], node['value'])
            if node['type'] == 'network.url':
                continue
        if 'children' in node and node['children']:
            decoded_network(node['children'], decoded_labels)
        if 'decoded_children' in node and node['decoded_children']:
            decoded_labels.append(node['type'])
            decoded_network(node['decoded_children'], decoded_labels)
            decoded_labels.pop()

def mixed_case(tree: list[dict[str, Any]]) -> None:
    for node in tree:
        if ('decoded' in node and node['value'].lower() == node['decoded'].lower()
                and not node['value'].isupper() and not node['value'].islower()
                and any(chr(v).isupper() and not chr(d).isupper()
                        for v, d in zip(node['value'], node['decoded']))):
            print(node['type'], node['value'], node['decoded'])

