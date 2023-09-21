from __future__ import annotations

import pefile
import regex as re

from multidecoder.node import Node
from multidecoder.registry import decoder

EXEDOS_RE = rb"(?s)This program cannot be run in DOS mode"
EXEHEADER_RE = rb"(?s)MZ.{32,1024}PE\000\000"


@decoder
def find_pe_files(data: bytes) -> list[Node]:
    """
    Searches for any PE files within data

    Args:
        data: The data to search
    Returns:
        A list of found PE files
    """
    pe_files: list[Node] = []
    offset = 0
    while offset < len(data):
        match = re.search(EXEHEADER_RE, data)
        if not match:
            return pe_files
        pe_data = data[offset:]
        if not re.search(EXEDOS_RE, pe_data):
            return pe_files
        try:
            pe = pefile.PE(data=pe_data)
            size = max(section.PointerToRawData + section.SizeOfRawData for section in pe.sections)
            if size == 0:
                return pe_files
            end = offset + size
            pe_files.append(Node("pe_file", data[offset:end], "", offset, end))
            offset = end
        except Exception:
            return pe_files
    return pe_files
