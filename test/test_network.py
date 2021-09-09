import re

from multidecoder.network import *

def test_ip_re():
    assert re.match(IP_RE, b'8.8.8.8') # valid ip address
    assert re.match(IP_RE, b'123.123.123.123') # up to three digits per group
    assert re.match(IP_RE, b'103.245.67.89') # all digits can appear

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

    # ip are found in context
    assert re.search(IP_RE, b'http://8.8.8.8/something').group() == b'8.8.8.8'

def test_domain_re():
    # normal domain
    assert re.match(DOMAIN_RE, b'www.google.com')
    # internationalized domain name
    assert re.match(DOMAIN_RE, b'xn--bcher-kva.example')
    # internationalized top level domain
    assert re.match(DOMAIN_RE, b'some.website.xn--4gbrim')

def test_email_re():
    assert re.match(EMAIL_RE, b'a_name@gmail.com')

def test_url_re():
    assert re.match(URL_RE, b'https://google.com')

def test_is_valid_domain_re():
    assert is_valid_domain(b'website.com')
    assert not is_valid_domain(b'website.notatld')

def test_is_public_ip():
    assert is_public_ip(b'8.8.8.8')
    assert not is_public_ip(b'0.0.0.0')
    assert not is_public_ip(b'10.0.192.33')
    assert not is_public_ip(b'127.0.0.1')
