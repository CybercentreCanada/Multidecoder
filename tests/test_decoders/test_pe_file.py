import os

import pytest

from multidecoder.decoders.pe_file import find_pe_files

TEST_DIR = os.path.dirname(__file__)


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"MZ a plaintext file should not count as a PE\x00\x00 file by coincidence. "
        b"This program cannot be run in DOS mode. This is obviously not PE content.",
        b"MZ",  # Truncated DOS header shouldn't raise exception.
    ],
)
def test_find_pe_files_false_pos(data):
    assert find_pe_files(data) == []
