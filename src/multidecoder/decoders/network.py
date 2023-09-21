"""Network indicators"""

from __future__ import annotations

import binascii
import contextlib
import socket
from ipaddress import AddressValueError, IPv4Address, IPv6Address
from urllib.parse import unquote_to_bytes, urlsplit

import regex as re

from multidecoder.domains import TOP_LEVEL_DOMAINS
from multidecoder.hit import match_to_hit
from multidecoder.keyword import MIXED_CASE_OBF
from multidecoder.node import Node, shift_nodes
from multidecoder.registry import decoder

# Type labels
DOMAIN_TYPE = "network.domain"
IP_TYPE = "network.ip"
EMAIL_TYPE = "network.email"
URL_TYPE = "network.url"

# Obfuscation labels
DOT_SEGMENT_OBF = "dot_segment"
IP_OBF = "ip_obfuscation"

# Regexes
_OCTET_RE = rb"(?:0x0*[a-f0-9]{1,2}|0*\d{1,3})"

DOMAIN_RE = rb"(?i)\b(?:[a-z0-9-]+\.)+(?:xn--[a-z0-9]{4,18}|[a-z]{2,12})(?![a-z.-])"
EMAIL_RE = rb"(?i)\b[a-z0-9._%+-]{3,}@(" + DOMAIN_RE[4:] + rb")\b"

IP_RE = rb"(?i)(?<![\w.])(?:" + _OCTET_RE + rb"[.]){3}" + _OCTET_RE + rb"(?![\w.])"

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


# Decoders
@decoder
def find_domains(data: bytes) -> list[Node]:
    """Find domains in data"""
    return [match_to_hit(DOMAIN_TYPE, match) for match in re.finditer(DOMAIN_RE, data) if is_domain(match.group())]


@decoder
def find_emails(data: bytes) -> list[Node]:
    """Find email addresses in data"""
    return [match_to_hit(EMAIL_TYPE, match) for match in re.finditer(EMAIL_RE, data) if is_domain(match.group(1))]


@decoder
def find_ips(data: bytes) -> list[Node]:
    """Find ip addresses in data"""
    return [parse_ip(match.group()).shift(match.start()) for match in re.finditer(IP_RE, data) if is_ip(match.group())]


@decoder
def find_urls(data: bytes) -> list[Node]:
    """Find URLs in data"""
    return [
        Node(
            URL_TYPE,
            *normalize_percent_encoding(match.group()),
            *match.span(),
            children=parse_url(match.group()),
        )
        for match in re.finditer(URL_RE, data)
        if is_url(match.group())
    ]


def parse_ip(ip: bytes) -> Node:
    """Parses an IPv4 address.

    Args:
        ip: The IPv4 address as a utf-8 encoded string of a represetation accepted by socket.inet_aton.
    Returns:
        A node with the normalized IPv4 address as it's value.
    """
    try:
        address = IPv4Address(socket.inet_aton(ip.decode()))
    except (OSError, AddressValueError, UnicodeDecodeError) as ex:
        raise ValueError(f"{ip!r} is not an IPv4 address") from ex
    compressed = address.compressed.encode()
    return Node(
        IP_TYPE,
        compressed,
        IP_OBF if compressed != ip else "",
        0,
        len(ip),
    )


def parse_ipv6(ip: bytes) -> Node:
    """Parses an IPv6 address.

    Args:
        ip: The IPv6 address as a utf-8 encoded string of a represetation accepted by socket.inet_pton.
    Returns:
        A node with the normalized IPv6 address as it's value.
    """
    try:
        address = IPv6Address(socket.inet_pton(socket.AF_INET6, ip.decode()))
    except (OSError, AddressValueError, UnicodeDecodeError) as ex:
        raise ValueError(f"{ip!r} is not an IPv6 address") from ex
    return Node(
        "network.ipv6",
        address.compressed.encode(),
        IP_OBF if address.compressed.encode() != ip else "",
        0,
        len(ip),
    )


def parse_url(url_text: bytes) -> list[Node]:
    """Parses a url into a decoding tree

    Args:
        url_text: the text of the url
    """
    out = []
    # Parse the url
    offset = 0
    url = urlsplit(url_text)
    if url.scheme:
        out.append(
            Node(
                "network.url.scheme",
                url.scheme,
                MIXED_CASE_OBF
                # url.scheme is normalized by urlsplit
                if url_text[0 : len(url.scheme)] not in (url.scheme, url.scheme.upper()) else "",
                0,
                len(url.scheme),
            )
        )
        offset += len(url.scheme) + 1  # scheme + :
    if url.netloc:
        offset += 2  # authority begins with //
        with contextlib.suppress(ValueError):
            out.extend(shift_nodes(parse_authority(url.netloc), offset))
        offset += len(url.netloc)
    if url.path:
        out.append(
            Node(
                "network.url.path",
                *normalize_path(url.path),
                offset,
                offset := offset + len(url.path),
            )
        )
    if url.query:
        offset += 1  # query starts with ?
        out.append(
            Node(
                "network.url.query",
                unquote_to_bytes(url.query),
                start=offset,
                end=(offset := offset + len(url.query)),
            )
        )
    if url.fragment:
        offset += 1  # fragment starts with #
        out.append(
            Node(
                "network.url.fragment",
                unquote_to_bytes(url.fragment),
                start=offset,
                end=offset + len(url.fragment),
            )
        )
    return out


def parse_authority(authority: bytes) -> list[Node]:
    """Split a URL's authority into it's consituent parts and unquote them"""
    out = []
    offset = 0
    userinfo, address = authority.rsplit(b"@", 1) if b"@" in authority else (b"", authority)
    username, password = userinfo.split(b":", 1) if b":" in userinfo else (userinfo, b"")
    host, _ = address.rsplit(b":", 1) if re.match(rb"(?r):\d*", address) else (address, b"")
    if username:
        out.append(
            Node(
                "network.url.username",
                unquote_to_bytes(username),
                "",
                0,
                len(username),
            )
        )
        offset += len(username)
    if password:
        offset += 1  # for the :
        out.append(
            Node(
                "network.url.password",
                unquote_to_bytes(password),
                "",
                offset,
                offset := offset + len(password),
            )
        )
    if not host:
        return out
    if userinfo:
        offset += 1  # for the @
    host = unquote_to_bytes(host)
    if host.startswith(b"["):
        if not host.endswith(b"]"):
            raise ValueError("Invalid IPv6 URL")
        with contextlib.suppress(ValueError):
            out.append(parse_ipv6(host[1:-1]).shift(offset + 1))
    else:
        try:
            out.append(parse_ip(host).shift(offset))
        except ValueError:
            if is_domain(host):
                out.append(Node("network.domain", host, "", offset, offset + len(host)))
    return out


def normalize_percent_encoding(uri: bytes) -> tuple[bytes, str]:
    """Normalize the percent encoding of a URI

    Un-encodes unreserved characters.
    Sets reserved percent encodings to uppercase.

    Args:
        url: the URI

    Returns:
        A tuple of the normalized URI and the obfuscation
    """

    def normalize_percent(match: re.Match[bytes]) -> bytes:
        """Normalize a single percent encoded byte"""
        byte = binascii.unhexlify(match.group(1))
        if b"A" <= byte <= b"Z" or b"a" <= byte <= b"z" or b"0" <= byte <= b"9" or byte in (b"-", b".", b"_", b"~"):
            return byte
        return match.group(0).upper()

    normalized = re.sub(
        rb"(?i)%([0-9a-f]{2})",
        normalize_percent,
        uri,
    )
    return normalized, "escape.percent" if len(normalized) < len(uri) else ""


def normalize_path(path: bytes) -> tuple[bytes, str]:
    """
    Decodes and normalize a url path.

    Normalized a url path by removing dot segments and decoding percent encodings,
    with the exception of %2F. %2F is not decoded so that the percent encoded path
    can be recovered from the normalized path. If %2F was decoded 'path/path' and
    'path%2Fpath' would be identical after decoding, preventing re-encoding them
    correctly.

    Args:
        path: the url path
    Returns:
        the normalized path,
        the obfuscation label for dot segment removal if there were dot segments
        (defaults to the empty string)

    """
    segments = [
        # Preserve / encoded as %2F to preserve segments
        # since path/path and path%2Fpath are not identical
        # per RFC 3986
        unquote_to_bytes(path_segment).replace(b"/", b"%2F")
        for path_segment in path.split(b"/")
    ]
    # Remove dot segments
    dotless: list[bytes] = []
    for segment in segments:
        if segment == b".":
            pass
        elif segment == b"..":
            if dotless:
                dotless.pop()
        else:
            dotless.append(segment)
    if dotless == [b""]:
        # Maintain starting / if the entire path is dot segments
        return b"/", "url.dotpath"
    return b"/".join(dotless), "url.dotpath" if len(dotless) < len(segments) else ""
