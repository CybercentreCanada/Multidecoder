
from multidecoder.hit import Hit
from multidecoder.analyzers.filename import find_executable_name


def test_find_executable_iexplore():
    assert find_executable_name(b'"\\Internet Explorer\\iexplore.exe"') == [Hit(b'iexplore.exe', '', 20, 32)]
    assert find_executable_name(b'IEXPLORE.EXE') == [Hit(b'IEXPLORE.EXE', '', 0, 12)]
