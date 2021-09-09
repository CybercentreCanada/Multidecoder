from multidecoder.analyze_data import analyze_data, KEY

def test_analyze_data_empty():
    assert analyze_data(b'') == {}

def test_analyze_data_url():
    assert analyze_data(b'https://some.domain.com') == {
        'network.url': {
            KEY: b'https://some.domain.com',
            'network.domain': b'some.domain.com'
        }
    }

def test_analyze_data_no_overlap():
    assert analyze_data(b'google.com, amazon.com, 8.8.8.8') == {
        'network.domain': [b'google.com', b'amazon.com'],
        'network.ip': b'8.8.8.8'
    }