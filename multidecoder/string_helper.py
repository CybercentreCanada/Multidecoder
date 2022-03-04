""" Helper functions for type coersion between string and bytes. """

from typing import Union


def make_str(string: Union[str, bytes]) -> str:
    """ Helper function for bytes to str coercion. """
    return string.decode(errors='ignore') if isinstance(string, bytes) else string


def make_bytes(string: Union[str, bytes]) -> bytes:
    """ Helper function for str to bytes coercion """
    return string.encode(errors='ignore') if isinstance(string, str) else string
