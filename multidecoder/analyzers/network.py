""" Network indicators

This module contains:
- Regexes for finding IPs, domains, email addresses, and URLs.
- Validators for checking potential network indicators.
- find_network_indicators, a function for finding all network indicators for a text.
"""

import re
import socket

from ipaddress import AddressValueError, IPv4Address
from typing import List, Union
from urllib.parse import unquote

from multidecoder.hit import Hit, match_to_hit
from multidecoder.domains import TOP_LEVEL_DOMAINS
from multidecoder.string_helper import make_str, make_bytes
from multidecoder.registry import analyzer

_OCTET_RE = rb'(?:0x0*[a-f0-9]{1,2}|0*\d{1,3})'
IP_RE = rb'(?i)\b(?:' + _OCTET_RE + rb'[.]){3}' + _OCTET_RE + rb'\b'
DOMAIN_RE = rb'(?i)\b(?:[a-z0-9-]+\.)+(?:xn--[a-z0-9]{4,18}|[a-z]{2,12})\b'
EMAIL_RE = rb'(?i)\b[a-z0-9._%+-]{3,}@(' + DOMAIN_RE[4:] + rb')\b'
URL_RE = rb'(?i)(?:ftp|https?)://(' + DOMAIN_RE[6:] + rb'|[0-9a-fx.]+)(?::[0-9]{1,5})?' \
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
        ip = parse_ip(match.group())
        if ip:
            out.append(Hit(ip, *match.span(), 'inet_aton' if ip != match.group() else ''))
    return out


@analyzer('network.url')
def find_urls(data: bytes) -> List[Hit]:
    """ Find URLs in data """
    return [match_to_hit(match) for match in re.finditer(URL_RE, data)
            if is_valid_domain(match.group(1)) or parse_ip(unquote(match.group(1)))]


def parse_ip(ip: Union[str, bytes]) -> bytes:
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
        address = IPv4Address(socket.inet_aton(make_str(ip)))
    except socket.error or AddressValueError:
        return b''
    if address.is_global and not address.is_multicast:
        return address.compressed.encode()
    else:
        return b''


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
