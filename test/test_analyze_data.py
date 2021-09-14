import pytest

from multidecoder.analyze_data import MultiDecoder

@pytest.fixture
def md():
    return MultiDecoder()

def test_analyze_data_empty(md):
    assert md.analyze_data(b'') == []

def test_analyze_data_url(md):
    assert md.analyze_data(b'https://some.domain.com') == [
        {
            'type': 'network.url',
            'value': b'https://some.domain.com',
            'children': [
                {
                    'type': 'network.domain',
                    'value': b'some.domain.com',
                    'children': []
                }
            ]

        }
    ]

def test_analyze_data_no_overlap(md):
    assert md.analyze_data(b'google.com, amazon.com, 8.8.8.8') == [
        {
            'type': 'network.domain',
            'value': b'google.com',
            'children': []
        },
        {
            'type': 'network.domain',
            'value': b'amazon.com',
            'children': []
        },
        {
            'type': 'network.ip',
            'value': b'8.8.8.8',
            'children': []
        },
    ]
