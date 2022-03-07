import os

from multidecoder.analyzers.pe_file import find_pe_files

TEST_DIR = os.path.dirname(__file__)


def test_find_pe_files():
    assert find_pe_files(b'') == []
    assert find_pe_files(b'MZ a plaintext file should not count as a PE\x00\x00 file by coincidence. '
                         b'This program cannot be run in DOS mode. This is obviously not PE content.') == []
