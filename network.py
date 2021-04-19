""" Network validation functions """

from ipaddress import AddressValueError, IPv4Address
from typing import Union

from domains import TOP_LEVEL_DOMAINS
from string_helper import make_str, make_bytes

def is_valid_domain(domain: Union[str, bytes]) -> bool:
    """ Checks if a domain is valid """
    parts = make_bytes(domain).rsplit(b'.', 1)
    if len(parts) != 2:
        return False
    domain, top_level = parts
    if top_level.upper() not in TOP_LEVEL_DOMAINS:
        return False
    return True

def is_valid_email(email: Union[str, bytes]) -> bool:
    """ Checks if an email address is valid """
    parts = make_bytes(email).split(b'@')
    if len(parts) != 2:
        return False
    username, domain = parts
    if not is_valid_domain(domain):
        return False
    return True

def is_public_ip(ip: Union[str, bytes]) -> bool:
    """
    Checks if an ipv4 address is valid and a standard public internet address

    rejects invalid addresses.
    rejects a valid address if it is:
        - a multicast address
        - a private address
        - a reserved address
    """
    try:
        address = IPv4Address(make_str(ip))
    except AddressValueError:
        return False
    return address.is_global and not address.is_multicast

