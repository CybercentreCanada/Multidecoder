from multidecoder.decoders.filename import find_executable_name
from multidecoder.node import Node


def test_find_executable_iexplore():
    assert find_executable_name(b'"\\Internet Explorer\\iexplore.exe"') == [
        Node("executable.filename", b"iexplore.exe", "", 20, 32)
    ]
    assert find_executable_name(b"IEXPLORE.EXE") == [Node("executable.filename", b"IEXPLORE.EXE", "", 0, 12)]
