import re
import pytest

from multidecoder.decoders.network import (
    DOMAIN_RE,
    EMAIL_RE,
    IP_RE,
    URL_RE,
    find_domains,
    is_domain,
    is_url,
    parse_ip,
)
from multidecoder.node import Node

# IP --------------------------------------------


def test_ip_re_matches_ips():
    assert re.match(IP_RE, b"127.0.0.1")  # valid ip address
    assert re.match(IP_RE, b"127.000.000.001")  # full ip
    assert re.match(IP_RE, b"123.123.123.123")  # up to three digits per group
    assert re.match(IP_RE, b"103.245.67.89")  # all digits can appear


def test_ip_re_group():
    # no more than 3 digits per group
    assert not re.search(IP_RE, b"1234.8.8.8")
    assert not re.search(IP_RE, b"8.1234.8.8")
    assert not re.search(IP_RE, b"8.8.1234.8")
    assert not re.search(IP_RE, b"8.8.8.1234")


def test_ip_re_dots():
    # no extra . or missing numbers
    assert not re.search(IP_RE, b"123..123.123.123")
    assert not re.search(IP_RE, b"123.123..123.123")
    assert not re.search(IP_RE, b"123.123.123..123")
    assert not re.search(IP_RE, b"123.123.123.")
    assert not re.search(IP_RE, b".123.123.123")


def test_ip_in_url():
    # ip are found in context
    ip = re.search(IP_RE, b"http://8.8.8.8/something")
    assert ip and ip.group() == b"8.8.8.8"


def test_ip_re_matches_octal():
    assert re.match(IP_RE, b"0177.0.0.01")
    assert re.match(IP_RE, b"00000000177.000.0.00000001")
    assert re.match(IP_RE, b"0177.0.0.0000001")
    assert re.match(IP_RE, b"000177.0000.00000.01")
    assert re.match(IP_RE, b"0000177.000000000000000000.00000000000.00000000001")
    assert re.match(
        IP_RE, b"00000000000000000000000000000000000000000000000000177.0.0.01"
    )


def test_ip_re_matches_hex():
    assert re.match(IP_RE, b"0x7f.0x0.0x0.0x1")


def test_ip_re_matches_mixed():
    assert re.match(IP_RE, b"0xac.000000000000000000331.0246.174")


def test_parse_ip():
    assert parse_ip(b"8.8.8.8") == Node("network.ip", b"8.8.8.8", "", 0, 7)


# Domain ----------------------------------------


def test_normal_domain():
    assert re.match(DOMAIN_RE, b"www.google.com")


def test_internationalized_domain_name():
    assert re.match(DOMAIN_RE, b"xn--bcher-kva.example")


def test_intenational_top_level_domain():
    assert re.match(DOMAIN_RE, b"some.website.xn--4gbrim")


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


# Email -----------------------------------------


def test_email_re():
    assert re.match(EMAIL_RE, b"a_name@gmail.com")


# URL -------------------------------------------


def test_url_re():
    assert re.match(URL_RE, b"https://google.com")


def test_url_re_ip():
    assert re.match(URL_RE, b"http://127.0.0.1")
    assert re.match(URL_RE, b"http://127.000.000.001")


def test_url_re_zero_suppresed_ip():
    assert re.match(URL_RE, b"http://127.1")
    assert re.match(URL_RE, b"http://192.168.1")
    assert re.match(URL_RE, b"http://127.0.00000000000000000000000000000000001")


def test_url_re_octal_ip():
    assert re.match(URL_RE, b"http://0177.0.0.01")
    assert re.match(URL_RE, b"http://00000000177.000.0.00000001")
    assert re.match(URL_RE, b"http://0177.0.0.0000001")
    assert re.match(URL_RE, b"http://000177.0000.00000.01")
    assert re.match(
        URL_RE, b"http://0000177.000000000000000000.00000000000.00000000001"
    )
    assert re.match(
        URL_RE, b"http://00000000000000000000000000000000000000000000000000177.0.0.01"
    )


def test_url_re_hex_ip():
    assert re.match(URL_RE, b"http://0x7f.0x0.0x0.0x1")
    assert re.match(URL_RE, b"http://0x7f000001")


def test_url_re_dword_ip():
    assert re.match(URL_RE, b"http://2130706433")


def test_url_re_mixed_ip():
    assert re.match(
        URL_RE, b"http://00000000000000000000000000000000000000000000000000177.1"
    )
    assert re.match(URL_RE, b"http://0x7f.1")
    assert re.match(URL_RE, b"http://127.0x1")
    assert re.match(URL_RE, b"http://172.14263982")
    assert re.match(URL_RE, b"http://0254.0xd9a6ae")
    assert re.match(URL_RE, b"http://0xac.000000000000000000331.0246.174")
    assert re.match(URL_RE, b"http://0331.14263982")


def test_url_re_encoded_ip():
    assert re.match(URL_RE, b"http://%31%32%37%2E%30%2E%30%2E%31")


@pytest.mark.parametrize(
    "url",
    [
        b"https://www.google.com.account.login:.@example.com",
        b"https://@example.com",
        b"https://:@example.com",
        b"https://google.com@micrsoft.com@adobe.com@example.com/path/to?param=value1&_param=value2"
        b"&trailing_url=https%3A%2F%2Fmalicious.com",
        # Example URIs from https://en.wikipedia.org/wiki/Uniform_Resource_Identifier#Example_URIs
        b"https://john.doe@www.example.com:123/forum/questions/?tag=networking&order=newest#top",
        b"http://[2001:db8::7]/c=GB?objectClass?one",
        b"ftp://192.0.2.16:80/",
        b"http://editing.com/resource/file.php?command=checkout",
    ],
)
def test_URL_RE_basic_auth(url):
    assert re.match(URL_RE, url).span() == (0, len(url))


@pytest.mark.parametrize(
    ("url", "suffix_len"),
    [
        (b"function('https://example.com/')", 2),
        (b"full sentence with a url https://example.com/.", 1),
        (b"part of a phrase with a url https://example.com/,", 1),
        (b"barefunction(https://example.com)", 1),
        (b'in a string content "https://example.com"works.', 7),
        (b"whitespaceless('https://example.com'){script;}", 11),
    ],
)
def test_URL_RE_in_context(url, suffix_len):
    assert re.search(URL_RE, url).end() == len(url) - suffix_len


def test_is_url():
    assert is_url(b"https://some.domain.com")
