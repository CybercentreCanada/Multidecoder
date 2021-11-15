
from multidecoder.hit import Hit
from multidecoder.analyzers.file_name import find_executable_name

def test_find_executable_iexplore():
    assert find_executable_name(b'"\\Internet Explorer\\iexplore.exe"') == [Hit(b'\\Internet Explorer\\iexplore.exe', 1, 32)]
    assert find_executable_name(b'IEXPLORE.EXE') == [Hit(b'IEXPLORE.EXE', 0, 12)]