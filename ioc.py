""" IOC finding functions """
import re

IPV4_RE = rb'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
IPV6_RE = rb'\b((?:[\da-f]{1,4}:){7,7}[\da-f]{1,4}|(?:[\da-f]{1,4}:){1,6}(:|(?::[\da-f]{1,4}){1,5}))\b'
DOMAIN_RE = rb'\b(?:[A-Z0-9-]+\.)+(?:XN--[A-Z0-9]{4,18}|[A-Z]{2,12})\b'
URI_RE = rb'(?:ftp|http|https)://' \
         rb'[A-Z0-9.-]{1,}\.(?:XN--[A-Z0-9]{4,18}|[a-z]{2,12}|[0-9]{1,3})' \
         rb'(?::[0-9]{1,5})?' \
         rb'(?:/[A-Z0-9/\-\.&%\$#=~\?_+]{3,200}){0,1}'

def check_network(data):
    """ Check for network indicators """
    return {
            'ip': re.findall(IPV4_RE, data),
            'domain': re.findall(DOMAIN_RE, data, flags=re.IGNORECASE),
            'uri': re.findall(URI_RE, data, flags=re.IGNORECASE)
    }

