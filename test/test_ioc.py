import re

from multidecoder.ioc import *

def test_ipv4_re():
    assert re.search(IP_RE, b'8.8.8.8') # valid ip address
    assert re.search(IP_RE, b'123.123.123.123') # up to three digits per group
    assert re.search(IP_RE, b'103.245.67.89') # all digits can appear

    # no more than 3 digits per group
    assert not re.search(IP_RE, b'1234.8.8.8')
    assert not re.search(IP_RE, b'8.1234.8.8')
    assert not re.search(IP_RE, b'8.8.1234.8')
    assert not re.search(IP_RE, b'8.8.8.1234')

    # no extra . or missing numbers
    assert not re.search(IP_RE, b'123..123.123.123')
    assert not re.search(IP_RE, b'123.123..123.123')
    assert not re.search(IP_RE, b'123.123.123..123')
    assert not re.search(IP_RE, b'123.123.123.')
    assert not re.search(IP_RE, b'.123.123.123')

    assert re.search(IP_RE, b'http://8.8.8.8/something').group(0) == b'8.8.8.8'
