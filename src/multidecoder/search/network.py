"""Network indicators"""

from __future__ import annotations

from ipaddress import AddressValueError, IPv4Address
from urllib.parse import urlsplit

import regex as re
from multidecoder.domains import TOP_LEVEL_DOMAINS
from multidecoder.search.hit import Hit

# Type labels
DOMAIN_TYPE = "network.domain"
IP_TYPE = "network.ip"
EMAIL_TYPE = "network.email"
URL_TYPE = "network.url"

# Regexes
_OCTET_RE = rb"(?:0x0*[a-f0-9]{1,2}|0*\d{1,3})"

DOMAIN_RE = rb"(?i)\b(?:[a-z0-9-]+\.)+(?:xn--[a-z0-9]{4,18}|[a-z]{2,12})(?![a-z.-])"
EMAIL_RE = rb"(?i)\b[a-z0-9._%+-]{3,}@(" + DOMAIN_RE[4:] + rb")\b"

IP_RE = rb"(?i)(?<![\w.])(?:" + _OCTET_RE + rb"[.]){3}" + _OCTET_RE + rb"(?![\w.])"

# TODO: Make url regex groups parse the subparts
# Using some weird ranges to shorten the regex:
# $-. is $%&'()*+,-. all of which are sub-delims $&'()*+, or unreserved .-
# $-/ is the same with /
# #-/ is the same with # and /
# #-& is #-/ but stopped before '
URL_RE = (
    rb"(?i)(?:ftp|https?)://"  # scheme
    rb"(?:[\w!$-.:;=~@]{,2000}@)?"  # userinfo
    rb"(?:(?!%5B)[%A-Z0-9.-]{4,253}|(?:\[|%5B)[%0-9A-F:]{3,117}(?:\]|%5D))"  # host
    rb"(?::[0-9]{0,5})?"  # port
    rb"(?:[/?#](?:[\w!#-/:;=@?~]{,2000}[\w!#-&(*+\-/:;=@?~])?)?"  # path, query and fragment
    # The final char class stops urls from ending in ' ) , or .
    # to prevent trailing characters from being included in the url.
)


# Regex validators
def is_domain(domain: bytes) -> bool:
    """Validates a potential domain.

    Checks the top level domain to ensure it is a registered top level domain.

    Args:
        domain: The domain to validate.
    Returns:
        Whether domain has a valid top level domain.
    """
    parts = domain.rsplit(b".", 1)
    if len(parts) != 2:
        return False
    name, tld = parts
    return bool(name and tld.upper() in TOP_LEVEL_DOMAINS)


def is_ip(ip: bytes) -> bool:
    """Validates a potential IPv4 address.

    Args:
        ip: The possible ip address.
    Returns:
        Whether ip is an IPv4 address.
    """
    try:
        IPv4Address(ip.decode("ascii"))
    except (AddressValueError, UnicodeDecodeError):
        return False
    return True


def is_url(url: bytes) -> bool:
    """Validates a potential URL.

    Checks that the url has a valid scheme and a hostname.

    Args:
       url: The possible url.
    Returns:
       Whether url is a URL.
    """
    try:
        split = urlsplit(url)
    except ValueError:
        return False
    return bool(split.scheme and split.hostname and split.scheme in (b"http", b"https", b"ftp"))


def find_domains(data: bytes) -> list[Hit]:
    """Find domains in data"""
    return [Hit.from_match(DOMAIN_TYPE, match) for match in re.finditer(DOMAIN_RE, data) if is_domain(match.group())]


def find_emails(data: bytes) -> list[Hit]:
    """Find email addresses in data"""
    return [Hit.from_match(EMAIL_TYPE, match) for match in re.finditer(EMAIL_RE, data) if is_domain(match.group(1))]


def find_ips(data: bytes) -> list[Hit]:
    """Find ip addresses in data"""
    return [Hit.from_match(IP_TYPE, match) for match in re.finditer(IP_RE, data) if is_ip(match.group())]


def find_urls(data: bytes) -> list[Hit]:
    """Find URLs in data"""
    return [
        Hit(
            URL_TYPE,
            *match.span(),
            children=[
                Hit.from_match("network.scheme", match, 1),
                Hit.from_match("network.username", match, 2),
                Hit.from_match("network.password", match, 3),
                # TODO: parse the hosts specific type
                # Hit.from_match("network.host", match, 4),
                Hit.from_match("network.port", match, 5),
                Hit.from_match("network.path", match, 6),
                Hit.from_match("network.query", match, 7),
                Hit.from_match("network.fragment", match, 8),
            ],
        )
        for match in re.finditer(URL_RE, data)
        if is_url(match.group())
    ]
