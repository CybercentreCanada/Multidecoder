""" IOC finding functions """

import re

from ipaddress import AddressValueError, IPv4Address, IPv6Address
from typing import Mapping, List

from string_helper import make_str

IP_RE = rb'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
DOMAIN_RE = rb'\b(?:[a-z0-9-]+\.)+(?:xn--[a-z0-9]{4,18}|[a-z]{2,12})\b'
URI_RE = rb'(?:ftp|http|https)://' \
         rb'[a-z0-9.-]+\.(?:xn--[a-z0-9]{4,18}|[a-z]{2,12}|[0-9]{1,3})' \
         rb'(?::[0-9]{1,5})?' \
         rb'(?:/[a-z0-9/\-\.&%\$#=~\?_+]{3,200})?'

def is_public_ip(ip: Union[str, bytes]) -> bool:
    """
    Checks if an ipv4 address is valid and a standard public internet address

    rejects invalid addresses.
    rejects a valid addresses if it is:
        - a multicast address
        - a private addresses
        - a reserved addresses
    """
    try:
        address = ipaddress.IPv4Address(make_str(ip))
    except AddressValueError:
        return False
    return address.is_global and not address.is_multicast

def check_network(data: bytes) -> Mapping[str, List[bytes]]:
    """ Check for network indicators """
    return {
            'domain': re.findall(DOMAIN_RE, data, flags=re.IGNORECASE),
            'ip': [ip for ip in re.findall(IP_RE, data) if is_public_ip4(ip)],
            'uri': re.findall(URI_RE, data, flags=re.IGNORECASE)
    }
