import re


from multidecoder.analyzers.network import DOMAIN_RE, EMAIL_RE, URL_RE, IP_RE
from multidecoder.analyzers.network import is_valid_domain, parse_ip
from multidecoder.analyzers.network import find_domains


# IP --------------------------------------------
def test_ip_re_matches_ips():
    assert re.match(IP_RE, b'127.0.0.1')  # valid ip address
    assert re.match(IP_RE, b'127.000.000.001')  # full ip
    assert re.match(IP_RE, b'123.123.123.123')  # up to three digits per group
    assert re.match(IP_RE, b'103.245.67.89')  # all digits can appear


def test_ip_re_group():
    # no more than 3 digits per group
    assert not re.search(IP_RE, b'1234.8.8.8')
    assert not re.search(IP_RE, b'8.1234.8.8')
    assert not re.search(IP_RE, b'8.8.1234.8')
    assert not re.search(IP_RE, b'8.8.8.1234')


def test_ip_re_dots():
    # no extra . or missing numbers
    assert not re.search(IP_RE, b'123..123.123.123')
    assert not re.search(IP_RE, b'123.123..123.123')
    assert not re.search(IP_RE, b'123.123.123..123')
    assert not re.search(IP_RE, b'123.123.123.')
    assert not re.search(IP_RE, b'.123.123.123')


def test_ip_in_url():
    # ip are found in context
    ip = re.search(IP_RE, b'http://8.8.8.8/something')
    assert ip and ip.group() == b'8.8.8.8'


def test_ip_re_matches_octal():
    assert re.match(IP_RE, b'0177.0.0.01')
    assert re.match(IP_RE, b'00000000177.000.0.00000001')
    assert re.match(IP_RE, b'0177.0.0.0000001')
    assert re.match(IP_RE, b'000177.0000.00000.01')
    assert re.match(IP_RE, b'0000177.000000000000000000.00000000000.00000000001')
    assert re.match(IP_RE, b'00000000000000000000000000000000000000000000000000177.0.0.01')


def test_ip_re_matches_hex():
    assert re.match(IP_RE, b'0x7f.0x0.0x0.0x1')


def test_ip_re_matches_mixed():
    assert re.match(IP_RE, b'0xac.000000000000000000331.0246.174')


def test_is_public_ip():
    assert parse_ip('8.8.8.8')[0]
    assert not parse_ip('0.0.0.0')[0]
    assert not parse_ip('10.0.192.33')[0]
    assert not parse_ip('127.0.0.1')[0]


# Domain ----------------------------------------

def test_normal_domain():
    assert re.match(DOMAIN_RE, b'www.google.com')


def test_internationalized_domain_name():
    assert re.match(DOMAIN_RE, b'xn--bcher-kva.example')


def test_intenational_top_level_domain():
    assert re.match(DOMAIN_RE, b'some.website.xn--4gbrim')


def test_is_valid_domain_re():
    assert is_valid_domain(b'website.com')
    assert not is_valid_domain(b'website.notatld')


def test_is_valid_domain_false_positives():
    assert not is_valid_domain(b'SET.NAME')


def test_find_domain_shell():
    assert find_domains(b'WScript.Shell, ript.Shell') == []


def test_find_domain_run():
    assert find_domains(b'WshShell.run') == []


def test_find_domain_save():
    assert find_domains(b'oShLnk.Save') == []


# Email -----------------------------------------

def test_email_re():
    assert re.match(EMAIL_RE, b'a_name@gmail.com')


# Url -------------------------------------------

def test_url_re():
    assert re.match(URL_RE, b'https://google.com')


def test_url_re_ip():
    assert re.match(URL_RE, b'http://127.0.0.1')
    assert re.match(URL_RE, b'http://127.000.000.001')


def test_url_re_zero_suppresed_ip():
    assert re.match(URL_RE, b'http://127.1')
    assert re.match(URL_RE, b'http://192.168.1')
    assert re.match(URL_RE, b'http://127.0.00000000000000000000000000000000001')


def test_url_re_octal_ip():
    assert re.match(URL_RE, b'http://0177.0.0.01')
    assert re.match(URL_RE, b'http://00000000177.000.0.00000001')
    assert re.match(URL_RE, b'http://0177.0.0.0000001')
    assert re.match(URL_RE, b'http://000177.0000.00000.01')
    assert re.match(URL_RE, b'http://0000177.000000000000000000.00000000000.00000000001')
    assert re.match(URL_RE, b'http://00000000000000000000000000000000000000000000000000177.0.0.01')


def test_url_re_hex_ip():
    assert re.match(URL_RE, b'http://0x7f.0x0.0x0.0x1')
    assert re.match(URL_RE, b'http://0x7f000001')


def test_url_re_dword_ip():
    assert re.match(URL_RE, b'http://2130706433')


def test_url_re_mixed_ip():
    assert re.match(URL_RE, b'http://00000000000000000000000000000000000000000000000000177.1')
    assert re.match(URL_RE, b'http://0x7f.1')
    assert re.match(URL_RE, b'http://127.0x1')
    assert re.match(URL_RE, b'http://172.14263982')
    assert re.match(URL_RE, b'http://0254.0xd9a6ae')
    assert re.match(URL_RE, b'http://0xac.000000000000000000331.0246.174')
    assert re.match(URL_RE, b'http://0331.14263982')


def test_url_re_encoded_ip():
    assert re.match(URL_RE, b'http://%31%32%37%2E%30%2E%30%2E%31')
