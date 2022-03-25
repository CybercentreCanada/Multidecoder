import regex as re

from multidecoder.analyzers.path import PATH_RE, WINDOWS_PATH_RE, find_path, find_windows_path


def test_empty_path():
    assert not re.search(PATH_RE, b'')


def test_empty_windows():
    assert not re.search(WINDOWS_PATH_RE, b'')


def test_absolute_path():
    assert re.match(PATH_RE, b'/path/file.txt')


def test_absolute_windows_path():
    assert re.match(WINDOWS_PATH_RE, b'\\path\\file.txt')


def test_dot_path():
    assert re.match(PATH_RE, b'./path/file.txt')


def test_dot_windows_path():
    assert re.match(WINDOWS_PATH_RE, b'.\\path\\file.txt')


def test_dotdot_path():
    assert re.match(PATH_RE, b'../path/file.txt')


def test_dotdot_windows_path():
    assert re.match(WINDOWS_PATH_RE, b'..\\path\\file.txt')


def test_windows_drive_path():
    assert re.match(WINDOWS_PATH_RE, b'C:\\path\\file.txt')


def test_find_path():
    assert find_path(b'/path/file.txt')


def test_find_windows_path():
    assert find_windows_path(b'\\path\\file.txt')
