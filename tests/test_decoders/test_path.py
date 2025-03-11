import pytest
import regex as re

from multidecoder.decoders.path import (
    PATH_RE,
    WINDOWS_PATH_RE,
    find_path,
    find_windows_path,
)
from multidecoder.node import Node


def test_empty_path():
    assert not re.search(PATH_RE, b"")


@pytest.mark.parametrize(
    "path",
    [
        b"/path/file.txt",
        b"./path/file.txt",
        b"../path/file.txt",
    ],
)
def test_path_re(path):
    assert re.match(PATH_RE, path)


def test_find_path():
    assert find_path(b"/path/file.txt")


@pytest.mark.parametrize(
    "path",
    [
        # https://learn.microsoft.com/en-us/dotnet/standard/io/file-path-formats
        Rb"C:\Documents\Newsletters\Summer2018.pdf",
        # Rb"\Program Files\Custom Utilities\StringFinder.exe" TODO: find way to support spaces without fpos
        Rb"2018\January.xlsx",
        Rb"..\Publications\TravelBrochure.pdf",
        Rb"C:\Projects\apilibrary\apilibrary.sln",
        Rb"C:Projects\apilibrary\apilibrary.sln",
        Rb"\\system07\C$\Test\Foo.txt",
        Rb"\\Server2\Share\Test\Foo.txt",
        Rb"\\.\C:\Test\Foo.txt",
        Rb"\\?\C:\Test\Foo.txt",
        Rb"\\.\Volume{b75e2c83-0000-0000-0000-602f00000000}\Test\Foo.txt",
        Rb"\\?\Volume{b75e2c83-0000-0000-0000-602f00000000}\Test\Foo.txt",
        Rb"\\.\UNC\Server\Share\Test\Foo.txt",
        Rb"\\?\UNC\Server\Share\Test\Foo.txt",
        Rb"c:\temp\test-file.txt",
        Rb"\\127.0.0.1\c$\temp\test-file.txt",
        Rb"\\LOCALHOST\c$\temp\test-file.txt",
        Rb"\\.\c:\temp\test-file.txt",
        Rb"\\?\c:\temp\test-file.txt",
        Rb"\\.\UNC\LOCALHOST\c$\temp\test-file.txt",
        # Additional tests
        Rb"\\some-domain.com@SSL\SERVER\file",
        Rb"\temp\test-file.txt",
        Rb".\temp\test-file.txt",
        Rb"..\temp\test-file.txt",
    ],
)
def test_windows_path_re(path):
    assert re.search(WINDOWS_PATH_RE, path).group() == path


@pytest.mark.parametrize(
    "fpos",
    [
        b"",
        b"\\",
        Rb"\"\\temp",
    ],
)
def test_windows_path_re_fpos(fpos):
    assert not re.search(WINDOWS_PATH_RE, fpos)


@pytest.mark.parametrize(
    ("path", "result"),
    [
        (
            Rb"c:\temp\test-file.txt",
            [
                Node(
                    "windows.path",
                    Rb"c:\temp\test-file.txt",
                    "",
                    0,
                    21,
                    children=[Node("filename", b"test-file.txt", "", 8, 21)],
                )
            ],
        ),
        (
            Rb"\\127.0.0.1\c$\temp\test-file.txt",
            [
                Node(
                    "windows.unc.path",
                    Rb"\\127.0.0.1\c$\temp\test-file.txt",
                    "",
                    0,
                    33,
                    children=[
                        Node("network.ip", b"127.0.0.1", "", 2, 11),
                        Node("filename", b"test-file.txt", "", 20, 33),
                    ],
                )
            ],
        ),
        (
            Rb"\\some-domain.com@SSL\SERVER\file",
            [
                Node(
                    "windows.unc.path",
                    Rb"\\some-domain.com@SSL\SERVER\file",
                    "",
                    0,
                    33,
                    children=[Node("network.domain", Rb"some-domain.com", "", 2, 17)],
                )
            ],
        ),
        (
            Rb"\\?\UNC\127.0.0.1\path\file.exe",
            [
                Node(
                    "windows.device.path",
                    Rb"\\?\UNC\127.0.0.1\path\file.exe",
                    "",
                    0,
                    31,
                    children=[
                        Node("network.ip", b"127.0.0.1", "", 8, 17),
                        Node("executable.filename", b"file.exe", "", 23, 31),
                    ],
                ),
            ],
        ),
        (
            Rb"c:\temp\foo\..\.\.\test-file",
            [
                Node(
                    "windows.path",
                    Rb"c:\temp\test-file",
                    "windows.dotpath",
                    0,
                    28,
                )
            ],
        ),
    ],
)
def test_find_windows_path(path, result):
    assert find_windows_path(path) == result
