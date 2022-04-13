import pytest

from multidecoder.multidecoder import Multidecoder


@pytest.fixture
def md():
    return Multidecoder()


def test_scan_empty(md):
    assert md.scan(b'') == []


def test_analyze_data_url(md):
    assert md.scan(b'https://some.domain.com') == [
        {
            'obfuscation': '',
            'type': 'network.url',
            'value': b'https://some.domain.com/',
            'start': 0,
            'end': 23,
            'children': []
        }
    ]


def test_scan_no_overlap(md):
    assert md.scan(b'google.com, amazon.com, 8.8.8.8') == [
        {
            'obfuscation': '',
            'type': 'network.domain',
            'value': b'google.com',
            'start': 0,
            'end': 10,
            'children': []
        },
        {
            'obfuscation': '',
            'type': 'network.domain',
            'value': b'amazon.com',
            'start': 12,
            'end': 22,
            'children': []
        },
        {
            'obfuscation': '',
            'type': 'network.ip',
            'value': b'8.8.8.8',
            'start': 24,
            'end': 31,
            'children': []
        }
    ]
