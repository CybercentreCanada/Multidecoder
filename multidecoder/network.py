""" Network indicators

This module contains:
- Regexes for finding IPs, domains, email addresses, and URLs
- Validators for checking potential network indicators
- find_network_indicators, a function for finding all network indicators for a text
"""

import re

from ipaddress import AddressValueError, IPv4Address
from typing import Mapping, Set, Union

from multidecoder.domains import TOP_LEVEL_DOMAINS
from multidecoder.string_helper import make_str, make_bytes

IP_RE = rb'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
DOMAIN_RE = rb'(?i)\b(?:[a-z0-9-]+\.)+(?:xn--[a-z0-9]{4,18}|[a-z]{2,12})\b'
EMAIL_RE = rb'(?i)\b[a-z0-9._%+-]{3,}@(' + DOMAIN_RE[4:] + rb')\b'
URL_RE = rb'(?i)(?:ftp|http|https)://(' + IP_RE + rb'|' + DOMAIN_RE[4:] + rb')(?::[0-9]{1,5})?' \
         rb'(?:/[a-z0-9/\-.&%$#=~?_+]{3,200})?'

def find_network_indicators(data: bytes) -> Mapping[str, Set[bytes]]:
    """ Find network indicators in data

    Args:
        data: The data to search
    """
    return {
            'domain': {domain for domain in re.findall(DOMAIN_RE, data)
                       if is_valid_domain(domain)},
            'email': {match.group(0) for match in re.finditer(EMAIL_RE, data)
                      if is_valid_domain(match.group(1))},
            'ip': {ip for ip in re.findall(IP_RE, data) if is_public_ip(ip)},
            'url': {match.group(0) for match in re.finditer(URL_RE, data)
                    if is_valid_domain(match.group(1)) or is_public_ip(match.group(1))}
    }

def is_public_ip(ip: Union[str, bytes]) -> bool:
    """
    Checks if an ipv4 address is valid and a standard public internet address

    rejects invalid addresses.
    rejects a valid address if it is:
        - a multicast address
        - a private address
        - a reserved address

    Args:
        ip: The ipv4 address to check
    Returns:
        Whether ip is a public ip address
    """
    try:
        address = IPv4Address(make_str(ip))
    except AddressValueError:
        return False
    return address.is_global and not address.is_multicast

def is_valid_domain(domain: Union[str, bytes]) -> bool:
    """ Checks if a domain is valid

    Checks the top level domain to ensure it is a registered top level domain

    Args:
        domain: The domain to validate
    Returns:
        Whether domain has a valid top level domain
    """
    parts = make_bytes(domain).rsplit(b'.', 1)
    if len(parts) != 2:
        return False
    domain, top_level = parts
    if top_level.upper() not in TOP_LEVEL_DOMAINS:
        return False
    return True
