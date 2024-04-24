from __future__ import annotations

import struct

import pefile
import regex as re

from multidecoder.node import Node
from multidecoder.registry import decoder

E_ELFANEW_OFFSET = 0x3C
E_ELFANEW_FORMAT = "<I"
E_ELFANEW_SIZE = struct.calcsize(E_ELFANEW_FORMAT)


@decoder
def find_pe_files(data: bytes) -> list[Node]:
    """Searches for any PE files within data."""
    pe_files: list[Node] = []
    # Regex is faster here than anything with str.find
    # because for str.find the loop has to be implemented in python
    len_data = len(data)
    for match in re.finditer(b"MZ", data):
        mz_offset = match.start()
        e_elfanew_location = mz_offset + E_ELFANEW_OFFSET
        if len_data < e_elfanew_location + E_ELFANEW_SIZE:
            continue
        (e_elfanew,) = struct.unpack_from(E_ELFANEW_FORMAT, data, e_elfanew_location)
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
        pe = pefile.PE(data=pe_data)
        return max((section.PointerToRawData + section.SizeOfRawData for section in pe.sections), default=0)
    except pefile.PEFormatError:
        return 0
