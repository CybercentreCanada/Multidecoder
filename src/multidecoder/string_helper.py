"""Helper functions for type coersion between string and bytes."""

from __future__ import annotations


def make_str(string: str | bytes) -> str:
    """Helper function for bytes to str coercion."""
    return string.decode(errors="ignore") if isinstance(string, bytes) else string


def make_bytes(string: str | bytes) -> bytes:
    """Helper function for str to bytes coercion"""
    return string.encode(errors="ignore") if isinstance(string, str) else string
