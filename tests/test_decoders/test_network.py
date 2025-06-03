import re

import pytest

from multidecoder.decoders.network import (
    DOMAIN_RE,
    EMAIL_RE,
    IP_RE,
    URL_RE,
    domain_is_false_positive,
    find_domains,
    find_ips,
    find_urls,
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


@pytest.mark.parametrize(
    "data",
    [
        b"<si><t>1.1.1.4</t></si>",
        b"ProductVersion\x004.0.0.1\x00",
        b"FileVersion\x004.0.0.1\x00",
        b"Version=4.0.0.1",
        b"0.0.0.0",
        b"Version\x00\x0012.3.0.1\x00",
        b"Version = 4.0.0.1",
        b"1.0.0.0",
        b"1.0.0.255",
        b"<a:t>  1.1.1.4 Section Title</a:t>",
        b"section 1.1.1.4",
        b"sec. 1.1.1.4",
        b"1.1.8.35-g8f5559c",
        b'version="1.2.0.58"',
    ],
)
def test_find_ips_false_positives(data):
    assert find_ips(data) == []


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


@pytest.mark.parametrize(
    "domain",
    [
        b"C:\\path\\looks-like-a-domain.com",
        b"C:\\path\\looks.like.a.domain.com",
        b"date.today()",
        b"domain.com-",
        b"variable.page_load",
        b'fi.search="',
        b"variable.call(",
        b"Microsoft.Win32",
    ],
)
def test_DOMAIN_RE_false_positives(domain):
    """Test that DOMAIN_RE does not match potential false positives"""
    assert not re.search(DOMAIN_RE, domain)


def test_is_valid_domain_re():
    assert is_domain(b"website.com")
    assert not is_domain(b"website.notatld")


@pytest.mark.parametrize(
    ("data", "domain"),
    [
        (b"config.edge.skype.com0", b"config.edge.skype.com"),
    ],
)
def test_DOMAIN_RE_context(data, domain):
    """Test that DOMAIN_RE matches in context"""
    assert re.search(DOMAIN_RE, data).group() == domain


@pytest.mark.parametrize(
    "domain",
    [
        b"WScript.Shell",
        b"ADODB.stream",
        b"SET.NAME",
        b"WshShell.run",
        b"this.day",
        b"this.global",
        b"this.it",
        b"this.it.next",
        b"this.name",
        b"this.zone",
        b"Array.prototype.map",
        b"CompIterator.prototype.next",
        b"Date.now",
        b"NativeDate.now",
        b"String.link",
        b"string.search",
        b"String.prototype.at",
        b"util.cc",
        b"libm.so",
        b"host.name",
        b"numbers.rs",
        b"test.cc",
        b"config.cc",
        b"colors.cc",
        b"reader.cc",
        b"process.name",
        b"subprocess.call",
        b"readme.md",
        b"compile.sh",
        b"authentication.click",
        b"system.management",
        b"microsoft.powershell.security",
        b"mem.total",
        b"e.business",
        b"t.center",
        b"a.family",
        b"e.global",
        b"view.name",
        b"x.properties",
        b"sub.name",
    ],
)
def test_domain_is_false_positive(domain):
    assert domain_is_false_positive(domain)


@pytest.mark.parametrize(
    "data",
    [
        b"K.cA",
    ],
)
def test_find_domain_fpos(data):
    assert find_domains(data) == []


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
        b"http://%5B%3A%3A1]",  # This works in Chrome and Edge.
        b"http://%5B::1]",  # The colons used to have to be percent encoded in edge and chrome, but not anymore.
        b"http://[::1%5D",  # You wouldn't think this would work, but it still does on Chrome and Edge.
        b"http://[::1%5D/path",  # Even handles the rest of the url just fine.
        # Large URLs
        b"http://youtube.com" + (b"%20" * 2000) + b"@google.com",
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
        (b"'https://example.com/'; ", b"https://example.com/"),
        (
            b"webhook_url = 'https://discord.com/api/webhooks/1244340229192548423/hRSjv25n8leII_p1pKEJSFSIUr_dLBX0-EY8ZMW3rakLh682QX0zByEpotnryCtRfK_Z'",
            b"https://discord.com/api/webhooks/1244340229192548423/hRSjv25n8leII_p1pKEJSFSIUr_dLBX0-EY8ZMW3rakLh682QX0zByEpotnryCtRfK_Z",
        ),
    ],
)
def test_URL_RE_context(data, url):
    """Test that URL_RE correctly matches URLs in context"""
    assert re.search(URL_RE, data).group() == url


def test_is_url():
    assert is_url(b"https://some.domain.com")


@pytest.mark.parametrize(
    ("data", "urls"),
    [
        (
            b" https://example.com/path'),.;still_url ",
            [
                Node(
                    "network.url",
                    b"https://example.com/path'),.;still_url",
                    "",
                    1,
                    39,
                    children=[
                        Node("network.url.scheme", b"https", "", 0, 5),
                        Node("network.domain", b"example.com", "", 8, 19),
                        Node("network.url.path", b"/path'),.;still_url", "", 19, 38),
                    ],
                )
            ],
        ),
        (
            b"                              'https://example.com/path'after_the_url",
            [
                Node(
                    "network.url",
                    b"https://example.com/path",
                    "",
                    31,
                    55,
                    children=[
                        Node("network.url.scheme", b"https", "", 0, 5),
                        Node("network.domain", b"example.com", "", 8, 19),
                        Node("network.url.path", b"/path", "", 19, 24),
                    ],
                )
            ],
        ),
        (
            b"https://example.com/path'still_the_url'",
            [
                Node(
                    "network.url",
                    b"https://example.com/path'still_the_url",
                    "",
                    0,
                    38,
                    children=[
                        Node("network.url.scheme", b"https", "", 0, 5),
                        Node("network.domain", b"example.com", "", 8, 19),
                        Node("network.url.path", b"/path'still_the_url", "", 19, 38),
                    ],
                )
            ],
        ),
        (
            b"'https://example.com",
            [
                Node(
                    "network.url",
                    b"https://example.com",
                    "",
                    1,
                    20,
                    children=[
                        Node("network.url.scheme", b"https", "", 0, 5),
                        Node("network.domain", b"example.com", "", 8, 19),
                    ],
                )
            ],
        ),
        (
            b"                    \x13https://example.com0thisisaftertheendoftheurl",
            [
                Node(
                    "network.url",
                    b"https://example.com",
                    "",
                    21,
                    40,
                    children=[
                        Node("network.url.scheme", b"https", "", 0, 5),
                        Node("network.domain", b"example.com", "", 8, 19),
                    ],
                )
            ],
        ),
    ],
)
def test_find_url(data, urls):
    assert find_urls(data) == urls
