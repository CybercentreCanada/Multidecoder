from __future__ import annotations

import struct

import pefile
import regex as re

from multidecoder.node import Node
from multidecoder.registry import decoder

E_ELFANEW_OFFSET = 0x3C


@decoder
def find_pe_files(data: bytes) -> list[Node]:
    """Searches for any PE files within data."""
    pe_files: list[Node] = []
    # Regex is faster here than anything with str.find
    # because for str.find the loop has to be implemented in python
    for match in re.finditer(b"MZ", data):
        mz_offset = match.start()
        (e_elfanew,) = struct.unpack_from("<I", data, mz_offset + E_ELFANEW_OFFSET)
        pe_offset = mz_offset + e_elfanew
        if data[pe_offset : pe_offset + 4] != b"PE\0\0":
            continue
        size = pe_size(data[mz_offset:])
        if size == 0:
            continue
        end = mz_offset + size
        pe_files.append(Node("pe_file", data[mz_offset:end], "", mz_offset, end))
    return pe_files


def pe_size(pe_data) -> int:
    """Find the end of a PE file.

    If there is a parsable PE file at the start of pe_data this function returns the offset of the end of that PE file
    Otherwise it returns 0. Uses the pefile library to parse the PE.
    """
    try:
        pe = pefile.PE(pe_data)
        return max(section.PointerToRawData + section.SizeOfRawData for section in pe.sections)
    except pefile.PEFormatError:
        return 0
