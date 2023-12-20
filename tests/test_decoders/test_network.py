import re

import pytest
from multidecoder.decoders.network import (
    DOMAIN_RE,
    EMAIL_RE,
    IP_RE,
    URL_RE,
    # find_domains,
    is_domain,
    is_url,
    parse_ip,
)
from multidecoder.node import Node

# IP --------------------------------------------


@pytest.mark.parametrize(
    "ip",
    [
        b"127.0.0.1",  # valid ip address
        b"123.123.123.123",  # up to three digits per group
        b"103.245.67.89",  # all digits can appear
        # Obfuscation techniques sourced from
        # https://www.hacksparrow.com/networking/many-faces-of-ip-address.html
        # but without the techniques that drop dots and dword notation.
        # Without the dots there are too many false positives.
        # octal ip address
        b"0177.0.0.01",
        b"00000000177.000.0.00000001",
        b"0177.0.0.0000001",
        b"000177.0000.00000.01",
        b"0000177.000000000000000000.00000000000.00000000001",
        b"00000000000000000000000000000000000000000000000000177.0.0.01",
        # hex ip address
        b"0x7f.0x0.0x0.0x1",
        # mixed ip address
        b"0xac.000000000000000000331.0246.174",
    ],
)
def test_IP_RE_match(ip):
    """Test that IP_RE matches expected ip addresses"""
    assert re.match(IP_RE, ip).end() == len(ip)


@pytest.mark.parametrize(
    "data",
    [
        # no more than 4 groups
        b"12.2.1.3.0",
        # no more than 3 digits per group
        b"1234.8.8.8",
        b"8.1234.8.8",
        b"8.8.1234.8",
        b"8.8.8.1234",
        # no extra . or missing numbers
        b"123..123.123.123",
        b"123.123..123.123",
        b"123.123.123..123",
        b"123.123.123.",
        b".123.123.123",
    ],
)
def test_IP_RE_false_positive(data):
    """Test that IP_RE does not match false positives"""
    assert re.search(IP_RE, data) is None


@pytest.mark.parametrize(("data", "ip"), [(b"http://8.8.8.8/something", b"8.8.8.8")])
def test_IP_RE_context(data, ip):
    """Test if IP_RE can find ip addresses in context"""
    assert re.search(IP_RE, data).group() == ip


def test_parse_ip():
    assert parse_ip(b"8.8.8.8") == Node("network.ip", b"8.8.8.8", "", 0, 7)


# Domain ----------------------------------------


@pytest.mark.parametrize(
    "domain",
    [
        b"www.google.com",  # normal domain
        b"xn--bcher-kva.example",  # international domain
        b"some.website.xn--4gbrim",  # intenational top level domain
    ],
)
def test_DOMAIN_RE_match(domain):
    """Test that DOMAIN_RE matches expected domains"""
    assert re.match(DOMAIN_RE, domain).end() == len(domain)


def test_is_valid_domain_re():
    assert is_domain(b"website.com")
    assert not is_domain(b"website.notatld")


# TODO: find a better way to avoid domain false positives than ignoring valid tlds
# def test_is_valid_domain_false_positives():
#     assert not is_valid_domain(b'SET.NAME')
#
#
# def test_find_domain_shell():
#     assert find_domains(b'WScript.Shell, ript.Shell') == []
#
#
# def test_find_domain_run():
#     assert find_domains(b'WshShell.run') == []
#
#
# def test_find_domain_save():
#     assert find_domains(b'oShLnk.Save') == []


@pytest.mark.parametrize(
    "data",
    [
        b"domain.com-",
    ],
)
def test_DOMAIN_RE_false_positive(data):
    """Test that DOMAIN_RE does not match potential false positives"""
    assert re.search(DOMAIN_RE, data) is None


@pytest.mark.parametrize(
    ("data", "domain"),
    [
        (b"config.edge.skype.com0", b"config.edge.skype.com"),
    ],
)
def test_DOMAIN_RE_context(data, domain):
    """Test that DOMAIN_RE matches in context"""
    assert re.search(DOMAIN_RE, data).group() == domain


# Email -----------------------------------------


def test_email_re():
    assert re.match(EMAIL_RE, b"a_name@gmail.com")


# URL -------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        # -- RFC 3986 compatible --
        b"https://google.com",
        b"http://127.0.0.1",
        # Example URIs from https://en.wikipedia.org/wiki/Uniform_Resource_Identifier#Example_URIs
        b"https://john.doe@www.example.com:123/forum/questions/?tag=networking&order=newest#top",
        b"http://[2001:db8::7]/c=GB?objectClass?one",
        b"ftp://192.0.2.16:80/",
        b"http://editing.com/resource/file.php?command=checkout",
        # Basic auth
        b"https://www.google.com.account.login:.@example.com",
        b"https://@example.com",
        b"https://:@example.com",
        b"https://google.com@micrsoft.com@adobe.com@example.com/path/to?param=value1&_param=value2"
        b"&trailing_url=https%3A%2F%2Fmalicious.com",
        #
        # -- Non RFC 3986 compatible urls that still work --
        #
        # Various ip address hacks sourced from:
        # https://www.hacksparrow.com/networking/many-faces-of-ip-address.html
        # Only format 1: dotted decimal is RFC 3986 compliant but the others are widely supported
        #
        # 0-optimized
        b"http://127.1",
        b"http://192.168.1",
        # octal
        b"http://0177.0.0.01",
        b"http://00000000177.000.0.00000001",
        b"http://0177.0.0.0000001",
        b"http://000177.0000.00000.01",
        b"http://0000177.000000000000000000.00000000000.00000000001",
        b"http://00000000000000000000000000000000000000000000000000177.0.0.01",
        # hexadecimal
        b"http://0x7f.0x0.0x0.0x1",
        b"http://0x7f000001",  # dotless
        # decimal / dword
        b"http://2130706433",
        # binary, not supported by inet_aton
        # b"http://01111111000000000000000000000001",
        # mixed
        b"http://127.0.00000000000000000000000000000000001",
        b"http://00000000000000000000000000000000000000000000000000177.1",
        b"http://0x7f.1",
        b"http://127.0x1",
        b"http://172.14263982",
        b"http://0254.0xd9a6ae",
        b"http://0xac.000000000000000000331.0246.174",
        b"http://0331.14263982",
        # IPv6
        # b'http://0000000000000:0000:0000:0000:0000:00000000000000:0000:1',  # Browsers don't support this,
        b"http://[0000:0000:0000:0000:0000:0000:0000:0001]",  # but this works fine.
        b"http://[0:0:0:0:0:0:0:1]",
        b"http://[0:0:0:0::0:0:1]",
        # encoded
        b"http://%31%32%37%2E%30%2E%30%2E%31",
        b"http://[%3A%3A%31]",
        # Full percent encoded IPv6 to test length constraints.
        b"http://[%30%30%30%30%3a%30%30%30%30%3a%30%30%30%30%3a%30%30%30%30%3a"
        b"%30%30%30%30%3a%30%30%30%30%3a%30%30%30%30%3a%30%30%30%31]",
        # Browser dependent, none of these work in Firefox.
        b"http://%5B%3A%3A1%5D",  # this works in Edge, but not Chrome.
        b"http://%5B%3A%3A1]",  # This works in Chrome and Edge, the colons have to be percent encoded.
        b"http://[::1%5D",  # You wouldn't think this would work, but it still does on Chrome and Edge.
        b"http://[::1%5D/path",  # Even handles the rest of the url just fine.
    ],
)
def test_URL_RE_matches(url):
    """Test that URL_RE matches expected URLs"""
    assert re.match(URL_RE, url).span() == (0, len(url))


@pytest.mark.parametrize(
    ("data", "url"),
    [
        # trailing characters tests
        (b"function('https://example.com/'){script;}", b"https://example.com/"),
        (b"full sentence with a url https://example.com/.", b"https://example.com/"),
        (
            b"part of a phrase with a url https://example.com/, still works",
            b"https://example.com/",
        ),
        (b"barefunction(https://example.com) works", b"https://example.com"),
        (b'in a string content "https://example.com"works.', b"https://example.com"),
    ],
)
def test_URL_RE_context(data, url):
    """Test that URL_RE correctly matches URLs in context"""
    assert re.search(URL_RE, data).group() == url


def test_is_url():
    assert is_url(b"https://some.domain.com")
