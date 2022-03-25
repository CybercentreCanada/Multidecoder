""" Network indicators

This module contains:
- Regexes for finding IPs, domains, email addresses, and URLs.
- Validators for checking potential network indicators.
- find_network_indicators, a function for finding all network indicators for a text.
"""

from __future__ import annotations

import regex as re
import socket

from ipaddress import AddressValueError, IPv4Address
from typing import List, Union
from urllib.parse import unquote

import hyperlink

from multidecoder.hit import Hit, match_to_hit
from multidecoder.domains import TOP_LEVEL_DOMAINS
from multidecoder.string_helper import make_bytes
from multidecoder.registry import analyzer

_OCTET_RE = rb'(?:0x0*[a-f0-9]{1,2}|0*\d{1,3})'
IP_RE = rb'(?i)\b(?:' + _OCTET_RE + rb'[.]){3}' + _OCTET_RE + rb'\b'
DOMAIN_RE = rb'(?i)\b(?:[a-z0-9-]+\.)+(?:xn--[a-z0-9]{4,18}|[a-z]{2,12})\b'
EMAIL_RE = rb'(?i)\b[a-z0-9._%+-]{3,}@(' + DOMAIN_RE[4:] + rb')\b'
URL_RE = rb'(?i)(?:ftp|https?)://[a-z0-9-%.]+(?::[0-9]{1,5})?' \
         rb'(?:/[a-z0-9/\-.&%$#=~?_+]{3,200})?'


@analyzer('network.domain')
def find_domains(data: bytes) -> List[Hit]:
    """ Find domains in data """
    return [match_to_hit(match) for match in re.finditer(DOMAIN_RE, data)
            if is_valid_domain(match.group())]


@analyzer('network.email')
def find_emails(data: bytes) -> List[Hit]:
    """ Find email addresses in data """
    return [match_to_hit(match) for match in re.finditer(EMAIL_RE, data)
            if is_valid_domain(match.group(1))]


@analyzer('network.ip')
def find_ips(data: bytes) -> List[Hit]:
    """ Find ip addresses in data """
    out = []
    for match in re.finditer(IP_RE, data):
        ip, obfuscation = parse_ip(match.group().decode())
        if ip:
            out.append(Hit(ip.encode(), obfuscation, *match.span()))
    return out


@analyzer('network.url')
def find_urls(data: bytes) -> List[Hit]:
    """ Find URLs in data """
    out = []
    for match in re.finditer(URL_RE, data):
        url, obfuscation = parse_url(match.group().decode())
        if url:
            out.append(Hit(url.encode(), obfuscation, *match.span()))
    return out


def parse_ip(ip: str) -> tuple[str, str]:
    """
    Checks if an ipv4 address is valid and a standard public internet address and normalizes it.

    accepts any ipv4 representation accepted by socket.inet_aton
    rejects invalid addresses.
    rejects a valid address if it is:
        - a multicast address,
        - a private address,
        - a reserved address

    Args:
        ip: The ipv4 address to validate.
    Returns:
        The normalized ip address if it is valid, otherwise the empty string
    """
    try:
        address = IPv4Address(socket.inet_aton(ip))
    except socket.error or AddressValueError:
        return '', ''
    if address.is_global and not address.is_multicast:
        return address.compressed, 'ip_obfuscation' if address.compressed != ip else ''
    else:
        return '', ''


def is_valid_domain(domain: Union[str, bytes]) -> bool:
    """ Checks if a domain is valid.

    Checks the top level domain to ensure it is a registered top level domain.

    Args:
        domain: The domain to validate.
    Returns:
        Whether domain has a valid top level domain.
    """
    parts = make_bytes(domain).rsplit(b'.', 1)
    if len(parts) != 2:
        return False
    domain, top_level = parts
    if top_level.upper() not in TOP_LEVEL_DOMAINS:
        return False
    return True


def parse_url(url_str: str) -> tuple[str, str]:
    decodings = []
    try:
        url = hyperlink.parse(url_str, decoded=False)
    except UnicodeDecodeError:
        return url_str, ''
    host = unquote(url.host)
    if host != url.host:
        decodings.append('percent.encoding')
    ip, obfuscation = parse_ip(host)
    if ip:
        decodings.append(obfuscation)
        url = url.replace(host=ip)
    return url.normalize().to_text(), '/>'.join(decodings)
