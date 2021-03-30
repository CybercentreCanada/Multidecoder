""" IOC finding functions """
import re
from typing import Mapping, List

IPV4_RE = rb'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
IPV6_RE = rb'\b((?:[\da-f]{1,4}:){7,7}[\da-f]{1,4}|(?:[\da-f]{1,4}:){1,6}(:|(?::[\da-f]{1,4}){1,5}))\b'
DOMAIN_RE = rb'\b(?:[A-Z0-9-]+\.)+(?:XN--[A-Z0-9]{4,18}|[A-Z]{2,12})\b'
URI_RE = rb'(?:ftp|http|https)://' \
         rb'[A-Z0-9.-]{1,}\.(?:XN--[A-Z0-9]{4,18}|[a-z]{2,12}|[0-9]{1,3})' \
         rb'(?::[0-9]{1,5})?' \
         rb'(?:/[A-Z0-9/\-\.&%\$#=~\?_+]{3,200}){0,1}'

def valid_ipv4(ip: bytes) -> bool:
    """ Validates an ip address """
    try:
        address = [int(n) for n in ip.split(b'.')]
    except ValueError:
        return False
    if (len(address) != 4 # wrong format
            or any(x > 255 for x in address) # out of ranage
            or address[0] == 0               # invalid destination address
            or address[3] in (0, 255)):      # ignore network identifier and broadcast addresses
        return False
    return True

def reserved_ipv4(ip:bytes) -> bool:
    """ Checks if a valid ip address is in a reserved address space"""
    address = [int(n) for n in ip.split(b'.')]
    assert len(address) == 4

    return address[0] in ( # /8 subnets
            0,  # current network (invalid destination)
            10, # private network
            127 # loopback
        ) or (address[0], address[1]) in ( # /16 subnets
            (192, 168), # private network
            (169, 254)  # link-local
        ) or (address[0], address[1], address[2]) in ( # /24 subnets
            (192, 0, 2),   # TEST-NET-1 documentation and examples
            (198, 51, 100),# TEST-NET-2
            (203, 0, 113), # TEST-NET-3
            (192, 88, 99)  # Former IPv6 to IPv4 relay
        ) or address[0] & 240 in ( # /4 subnets
            224, # ip multiclass
            240  # future use
        ) or (address[0] == 100 and address[1] & 192 == 64 # /10 shared address space for carrier NAT
        or address[0] == 172 and address[1] & 240 == 16    # /12 private network
        or address[0] == 198 and address[1] & 254 == 18)   # /15 private network (benchmarking)

def check_network(data: bytes) -> Mapping[str, List[bytes]]:
    """ Check for network indicators """
    return {
            'ip': [ip for ip in re.findall(IPV4_RE, data) if valid_ipv4(ip) and not reserved_ipv4(ip)],
            'domain': re.findall(DOMAIN_RE, data, flags=re.IGNORECASE),
            'uri': re.findall(URI_RE, data, flags=re.IGNORECASE)
    }
