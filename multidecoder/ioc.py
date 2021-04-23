""" IOC finding functions """

import re

from typing import Mapping, List

from string_helper import make_str
from network import is_public_ip

IP_RE = rb'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
DOMAIN_RE = rb'\b(?:[a-z0-9-]+\.)+(?:xn--[a-z0-9]{4,18}|[a-z]{2,12})\b'
URI_RE = rb'(?:ftp|http|https)://' \
         rb'[a-z0-9.-]+\.(?:xn--[a-z0-9]{4,18}|[a-z]{2,12}|[0-9]{1,3})' \
         rb'(?::[0-9]{1,5})?' \
         rb'(?:/[a-z0-9/\-\.&%\$#=~\?_+]{3,200})?'

def check_network(data: bytes) -> Mapping[str, List[bytes]]:
    """ Check for network indicators """
    return {
            'domain': re.findall(DOMAIN_RE, data, flags=re.IGNORECASE),
            'ip': [ip for ip in re.findall(IP_RE, data) if is_public_ip(ip)],
            'uri': re.findall(URI_RE, data, flags=re.IGNORECASE)
    }
