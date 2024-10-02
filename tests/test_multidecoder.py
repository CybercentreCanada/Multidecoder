import pytest

from multidecoder.multidecoder import Multidecoder, Node


@pytest.fixture
def md():
    return Multidecoder()


def test_scan_empty(md):
    assert md.scan(b"") == Node("", b"", "", 0, 0)


def test_analyze_data_url(md):
    assert md.scan(b"https://some.domain.com").children == [
        Node(
            "network.url",
            b"https://some.domain.com",
            "",
            0,
            23,
            children=[
                Node("network.url.scheme", b"https", "", 0, 5),
                Node("network.domain", b"some.domain.com", "", 8, 23),
            ],
        )
    ]


def test_scan_no_overlap(md):
    assert md.scan(b"google.com, amazon.com, 8.8.8.8").children == [
        Node("network.domain", b"google.com", "", 0, 10),
        Node("network.domain", b"amazon.com", "", 12, 22),
        Node("network.ip", b"8.8.8.8", "", 24, 31),
    ]
