"""
xortool.py
====================

A tool to do some xor analysis:

  - guess the key length (based on count of equal chars)
  - guess the key (base on knowledge of most frequent char)

Adapted from hellman's xortool project (https://github.com/hellman/xortool) for use as library.


License: https://opensource.org/license/MIT

Copyright 2011 hellman
Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
documentation files (the “Software”), to deal in the Software without restriction, including without limitation the
rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit
persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the
Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
"""

from __future__ import annotations

import string
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Container


class AnalysisError(Exception):
    pass


def xortool(
    ciphertext: bytes,
    try_chars: list[int],
    known_key_length: int | None = None,
    *,
    max_key_length: int = 65,
    text_charset: Container[int] = string.printable.encode(),
    known_plain: bytes = b"",
    filter_output: object = False,
) -> list[bytes]:
    if not known_key_length:
        known_key_length = guess_key_length(ciphertext, max_key_length)

    (probable_keys, key_char_used) = guess_probable_keys_for_chars(ciphertext, try_chars, known_key_length)

    return produce_plaintexts(ciphertext, probable_keys, text_charset, known_plain, filter_output)


# -----------------------------------------------------------------------------
# KEYLENGTH GUESSING SECTION
# -----------------------------------------------------------------------------


def guess_key_length(text: bytes, max_key_length: int) -> int:
    """
    Try key lengths from 1 to max_key_length and print local maximums

    Set key_length to the most possible if it's not set by user.
    """
    fitnesses = calculate_fitnesses(text, max_key_length)
    if not fitnesses:
        raise AnalysisError("No candidates for key length found! Too small file?")

    guess_divisors(fitnesses, max_key_length)
    return get_max_fitnessed_key_length(fitnesses)


def calculate_fitnesses(text: bytes, max_key_length: int) -> list[tuple[int, float]]:
    """Calculate fitnesses for each keylen"""
    prev = 0.0
    pprev = 0.0
    fitnesses = []
    for key_length in range(1, max_key_length + 1):
        # smaller key-length with nearly the same fitness is preferable
        fitness = count_equals(text, key_length) / (max_key_length + key_length**1.5)

        if pprev < prev and prev > fitness:  # local maximum
            fitnesses += [(key_length - 1, prev)]

        pprev = prev
        prev = fitness

    if pprev < prev:
        fitnesses += [(key_length - 1, prev)]

    return fitnesses


def calculate_fitness_sum(fitnesses: list[tuple[int, float]]) -> float:
    return sum([f[1] for f in fitnesses])


def count_equals(text: bytes, key_length: int) -> int:
    """Count equal chars count for each offset and sum them"""
    equals_count = 0
    if key_length >= len(text):
        return 0

    for offset in range(key_length):
        chars_count = chars_count_at_offset(text, key_length, offset)
        equals_count += max(chars_count.values()) - 1  # why -1? don't know
    return equals_count


def guess_divisors(fitnesses: list[tuple[int, float]], max_key_length: int) -> int:
    """
    Guesses common divisors and returns the most common divisor
    """
    divisors_counts = [0] * (max_key_length + 1)
    for key_length, _ in fitnesses:
        for number in range(3, key_length + 1):
            if key_length % number == 0:
                divisors_counts[number] += 1
    max_divisors = max(divisors_counts)

    limit = 3
    ret = 2
    for number, divisors_count in enumerate(divisors_counts):
        if divisors_count == max_divisors:
            ret = number
            limit -= 1
            if limit == 0:
                return ret
    return ret


def get_max_fitnessed_key_length(fitnesses: list[tuple[int, float]]) -> int:
    max_fitness = 0.0
    max_fitnessed_key_length = 0
    for key_length, fitness in fitnesses:
        if fitness > max_fitness:
            max_fitness = fitness
            max_fitnessed_key_length = key_length
    return max_fitnessed_key_length


def chars_count_at_offset(text: bytes, key_length: int, offset: int) -> dict[int, int]:
    chars_count: dict[int, int] = {}
    for pos in range(offset, len(text), key_length):
        c = text[pos]
        if c in chars_count:
            chars_count[c] += 1
        else:
            chars_count[c] = 1
    return chars_count


# -----------------------------------------------------------------------------
# KEYS GUESSING SECTION
# -----------------------------------------------------------------------------


def guess_probable_keys_for_chars(
    text: bytes, try_chars: list[int], known_key_length: int
) -> tuple[list[bytes], dict[bytes, int]]:
    """
    Guess keys for list of characters.
    """
    probable_keys = []
    key_char_used = {}

    for c in try_chars:
        keys = guess_keys(text, c, known_key_length)
        for key in keys:
            key_char_used[key] = c
            if key not in probable_keys:
                probable_keys.append(key)

    return probable_keys, key_char_used


def guess_keys(text: bytes, most_char: int, known_key_length: int) -> list[bytes]:
    """
    Generate all possible keys for key length
    and the most possible char
    """
    key_length = known_key_length
    key_possible_bytes: list[list[int]] = [[] for _ in range(key_length)]

    for offset in range(key_length):  # each byte of key<
        chars_count = chars_count_at_offset(text, key_length, offset)
        max_count = max(chars_count.values())
        for char in chars_count:
            if chars_count[char] >= max_count:
                key_possible_bytes[offset].append(char ^ most_char)

    return all_keys(key_possible_bytes)


def all_keys(key_possible_bytes: list[list[int]], key_part: tuple[int, ...] = (), offset: int = 0) -> list[bytes]:
    """
    Produce all combinations of possible key chars
    """
    keys = []
    if offset >= len(key_possible_bytes):
        return [bytes(key_part)]
    for c in key_possible_bytes[offset]:
        keys += all_keys(key_possible_bytes, (*key_part, c), offset + 1)
    return keys


# -----------------------------------------------------------------------------
# RETURNS PERCENTAGE OF VALID TEXT CHARS
# -----------------------------------------------------------------------------


def percentage_valid(text: bytes, text_charset: Container[int]) -> float:
    "Returns percentage of valid text chars"
    x = 0.0
    for c in text:
        if c in text_charset:
            x += 1
    return x / len(text)


# -----------------------------------------------------------------------------
# DEXOR TEXT
# -----------------------------------------------------------------------------


def dexor(text: bytes, key: bytes) -> bytes:
    mod = len(key)
    return bytes(key[index % mod] ^ char for index, char in enumerate(text))


# -----------------------------------------------------------------------------
# PRODUCE OUTPUT
# -----------------------------------------------------------------------------


def produce_plaintexts(
    ciphertext: bytes,
    keys: list[bytes],
    text_charset: Container[int],
    known_plain: bytes,
    filter_output: object,
):
    """
    Produce plaintext variant for each possible key,
    returns the plaintext, the key that produced it,
    the percentage of valid characters and
    the most frequent character used
    """
    threshold_valid = 95

    out = []
    for key in keys:
        dexored = dexor(ciphertext, key)
        # ignore saving file when known plain is provided and output doesn't contain it
        if known_plain and known_plain not in dexored:
            continue
        perc = round(100 * percentage_valid(dexored, text_charset))
        if not filter_output or (filter_output and perc > threshold_valid):
            out.append(dexored)
    return out
