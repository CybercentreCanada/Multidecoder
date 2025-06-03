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

# Specifically allowing 0 after domain names for PE strings
DOMAIN_RE = rb"(?i)(?<![-\w.\\_])(?:[a-z0-9-]+\.)+(?:xn--[a-z0-9]{4,18}|[a-z]{2,12})(?![a-z1-9.(=_-])"
EMAIL_RE = rb"(?i)\b[a-z0-9._%+-]{3,}@(" + DOMAIN_RE[4:] + rb")\b"

IP_RE = rb"(?i)(?<![\w.-])(?:" + _OCTET_RE + rb"[.]){3}" + _OCTET_RE + rb"(?![\w.-])"

# Using some weird ranges to shorten the regex:
# $-. is $%&'()*+,-. all of which are sub-delims $&'()*+, or unreserved .-
# $-/ is the same with /
# #-/ is the same with # and /
# #-& is #-/ but stopped before '
URL_RE = (
    rb"(?i)(?:ftp|https?)://"  # scheme
    rb"(?:[\w!$-.:;=~@]*@)?"  # userinfo
    rb"(?:(?!%5B)[%A-Z0-9.-]{4,253}|(?:\[|%5B)[%0-9A-F:]{3,117}(?:\]|%5D))"  # host
    rb"(?::[0-6]?[0-9]{0,4})?"  # port
    rb"(?:[/?#](?:[\w!#-/:;=@?~]*[\w!#-&(*+\-/:=@?~])?)?"  # path, query and fragment
    # The final char class stops urls from ending in ' ) , . or ;
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
        split.port  # noqa: B018 urlsplit.port is a property that does validation and raises ValueError if it fails.
    except ValueError:
        return False
    return bool(split.scheme and split.hostname and split.scheme in (b"http", b"https", b"ftp"))


# False Positives


def domain_is_false_positive(domain: bytes) -> bool:
    """Flag common forms of dotted text that can be mistaken for domains."""
    domain_lower = domain.lower()
    split = domain_lower.split(b".")
    if len(split) < 2:
        return True
    tld = split[-1]
    root = split[0]

    # Common variable roots
    root_fpos = {
        b"abbrev",
        b"activate",
        b"adodb",
        b"agent",
        b"algorithm",
        b"alias",
        b"analytic",
        b"analytics",
        b"append",
        b"appendreplace",
        b"aquota",
        b"arena",
        b"arenastring",
        b"array",
        b"arrayprototype",
        b"ascii",
        b"at",
        b"attrtable",
        b"authentication",
        b"barrier",
        b"base64",
        b"basetype",
        b"basetypefactory",
        b"basic",
        b"before",
        b"bignum",
        b"bind",
        b"blake2",
        b"build",
        b"button",
        b"bytestream",
        b"cgroup",
        b"charconv",
        b"check",
        b"city",
        b"clause",
        b"clean",
        b"clock",
        b"code-of-conduct",
        b"colors",
        b"column",
        b"common",
        b"compile",
        b"conditions",
        b"config",
        b"constructor",
        b"context",
        b"contributing",
        b"conversion",
        b"convert",
        b"cord",
        b"core",
        b"crash",
        b"crc32",
        b"crc32c",
        b"crypto",
        b"ctrl-alt-del",
        b"curve25519",
        b"cycleclock",
        b"data",
        b"date",
        b"debbugger",
        b"decimal",
        b"default",
        b"deferred",
        b"demangle",
        b"descripters",
        b"destructible",
        b"di",
        b"direction",
        b"directions",
        b"div",
        b"division",
        b"document",
        b"double-to-string",
        b"downcalls",
        b"duration",
        b"ecdh",
        b"ecos",
        b"el",
        b"electron",
        b"elem",
        b"email",
        b"emergency",
        b"enduser",
        b"engine",
        b"error",
        b"escape",
        b"escaping",
        b"event",
        b"eventstudy",
        b"example",
        b"examples",
        b"exit",
        b"expr",
        b"extention",
        b"fast-dtoa",
        b"features",
        b"fence",
        b"field",
        b"file",
        b"fixed-dtoa",
        b"flag",
        b"flags",
        b"float",
        b"float32",
        b"float64",
        b"fnmatch",
        b"forkunsafe",
        b"format",
        b"frame",
        b"function",
        b"functionprototype",
        b"futex",
        b"gadget",
        b"gadgets",
        b"geo",
        b"gettingstarted",
        b"glob",
        b"global",
        b"globals",
        b"graph",
        b"graphcycles",
        b"graphical",
        b"grid",
        b"halt",
        b"hash",
        b"heapsort",
        b"histogram",
        b"host",
        b"httpd",
        b"index",
        b"info",
        b"infostream",
        b"init",
        b"initialize",
        b"initrd-fs",
        b"initrd-root-fs",
        b"inline",
        b"input",
        b"install",
        b"int",
        b"int16",
        b"int32",
        b"int64",
        b"int128",
        b"interceptor",
        b"ipconf",
        b"it",
        b"item",
        b"key",
        b"keydown",
        b"keyset",
        b"layer",
        b"layerswitcher",
        b"legacy",
        b"lexing",
        b"lhash",
        b"lib",
        b"line",
        b"lnkinfo",
        b"local-fs",
        b"local-fs-pre",
        b"location",
        b"logging",
        b"lossy",
        b"manager",
        b"match",
        b"mem",
        b"memfd",
        b"memutil",
        b"memory",
        b"message",
        b"metatrace",
        b"method",
        b"metrics",
        b"microsoft",
        b"mount",
        b"mutex",
        b"multi-user",
        b"myapplication",
        b"nativedate",
        b"netinfo",
        b"network",
        b"network-online",
        b"new",
        b"notification",
        b"nss",
        b"nss-lookup",
        b"nullguard",
        b"number",
        b"numbers",
        b"obj",
        b"object",
        b"offset",
        b"offsets",
        b"og",
        b"once",
        b"operation",
        b"option",
        b"options",
        b"original",
        b"originalresults",
        b"org",
        b"os",
        b"oshlnk",
        b"ostringstream",
        b"output",
        b"package",
        b"packagejson",
        b"parentoffset",
        b"parser",
        b"path",
        b"paths",
        b"pattern",
        b"pickle",
        b"pipe",
        b"pkey",
        b"platform",
        b"port",
        b"poweroff",
        b"printable",
        b"process",
        b"profile",
        b"program",
        b"progress",
        b"property",
        b"proto",
        b"prtime",
        b"prtracer",
        b"quicksort",
        b"rand",
        b"randen",
        b"random",
        b"reader",
        b"readme",
        b"reboot",
        b"rect",
        b"rectangle",
        b"refcount",
        b"reference",
        b"remote",
        b"remote-fs",
        b"remote-fs-pre",
        b"repository",
        b"rescue",
        b"response",
        b"restore",
        b"result",
        b"results",
        b"ribbon",
        b"roots",
        b"rpcbind",
        b"runtests",
        b"rvalue",
        b"security",
        b"sequence",
        b"service",
        b"set",
        b"settings",
        b"sha1",
        b"sha256",
        b"sha512",
        b"shift",
        b"shutdown",
        b"signal",
        b"signalhandler",
        b"signals",
        b"sigpwr",
        b"simple",
        b"socket",
        b"sockets",
        b"source",
        b"spec",
        b"spinlock",
        b"src",
        b"stack",
        b"stacktrace",
        b"startup",
        b"startvscode",
        b"state",
        b"status",
        b"statusor",
        b"str",
        b"strcat",
        b"strerror",
        b"string",
        b"string-to-double",
        b"stringpiece",
        b"strlcpy",
        b"strtod",
        b"strutil",
        b"sub",
        b"subprocess",
        b"substitute",
        b"swap",
        b"symbolize",
        b"syntaxerror",
        b"sysinfo",
        b"sysinit",
        b"syslog",
        b"system",
        b"table",
        b"tactic",
        b"tagging",
        b"tail",
        b"task",
        b"tasks",
        b"technique",
        b"test",
        b"testdomain",
        b"thread",
        b"time",
        b"timer",
        b"timers",
        b"time-sync",
        b"timezone",
        b"token",
        b"tomcat",
        b"tracing",
        b"track",
        b"trie",
        b"tween",
        b"ui",
        b"uint16",
        b"uint32",
        b"uint64",
        b"umount",
        b"unix",
        b"unscaledcycleclock",
        b"unwinder",
        b"upgrade",
        b"urandom",
        b"user",
        b"utf8",
        b"util",
        b"utils",
        b"uuid",
        b"value",
        b"values",
        b"vector",
        b"verinfo",
        b"version",
        b"versioninfo",
        b"view",
        b"visit",
        b"vlog",
        b"window",
        b"wrapping",
        b"wscript",
        b"wshshell",
        b"zlib",
        b"zone",
    }
    reliable_tlds = {
        # Original tlds
        b"com",
        b"net",
        b"org",
        b"edu",
        b"mil",
        b"gov",
        b"arpa",
        # Country tlds, filtered for common fpos
        b"ac",
        b"ad",
        b"ae",
        b"af",
        b"ag",
        b"ai",
        b"al",
        b"am",
        b"ao",
        b"aq",
        b"ar",
        b"au",
        b"aw",
        b"ax",
        b"az",
        b"ba",
        b"bd",
        b"be",
        b"bf",
        b"bg",
        b"bh",
        b"bi",
        b"bj",
        b"bm",
        b"bn",
        b"bo",
        b"br",
        b"bs",
        b"bt",
        b"bv",
        b"bw",
        b"by",
        b"bz",
        b"ca",
        b"cd",
        b"cf",
        b"cg",
        b"ch",
        b"ck",
        b"cl",
        b"cm",
        b"cn",
        b"co",
        b"cr",
        b"cu",
        b"cv",
        b"cw",
        b"cx",
        b"cy",
        b"cz",
        b"de",
        b"dj",
        b"dk",
        b"dm",
        b"dz",
        b"ec",
        b"er",
        b"es",
        b"et",
        b"eu",
        b"fi",
        b"fj",
        b"fk",
        b"fm",
        b"fo",
        b"fr",
        b"ga",
        b"gb",
        b"gd",
        b"ge",
        b"gl",
        b"gm",
        b"gn",
        b"gp",
        b"gq",
        b"gr",
        b"gs",
        b"gt",
        b"gu",
        b"gw",
        b"gy",
        b"hk",
        b"hm",
        b"hn",
        b"hr",
        b"ht",
        b"hu",
        b"ie",
        b"il",
        b"im",
        b"iq",
        b"ir",
        b"je",
        b"jm",
        b"jo",
        b"jp",
        b"ke",
        b"kg",
        b"kh",
        b"ki",
        b"km",
        b"kn",
        b"kp",
        b"kr",
        b"kw",
        b"ky",
        b"kz",
        b"la",
        b"lc",
        b"li",
        b"lk",
        b"lr",
        b"ls",
        b"lt",
        b"lu",
        b"lv",
        b"ly",
        b"ma",
        b"mc",
        b"me",
        b"mg",
        b"mh",
        b"ml",
        b"mn",
        b"mo",
        b"mp",
        b"mq",
        b"mr",
        b"mt",
        b"mu",
        b"mv",
        b"mw",
        b"mx",
        b"my",
        b"mz",
        b"na",
        b"nc",
        b"ne",
        b"nf",
        b"ng",
        b"ni",
        b"nl",
        b"np",
        b"nr",
        b"nu",
        b"nz",
        b"om",
        b"pa",
        b"pe",
        b"pf",
        b"pg",
        b"ph",
        b"pk",
        b"pn",
        b"pr",
        b"ps",
        b"pt",
        b"pw",
        b"qa",
        b"re",
        b"ro",
        b"ru",
        b"rw",
        b"sa",
        b"sb",
        b"sc",
        b"sd",
        b"se",
        b"sg",
        b"si",
        b"sj",
        b"sk",
        b"sl",
        b"sm",
        b"sn",
        b"sr",
        b"ss",
        b"st",
        b"su",
        b"sv",
        b"sx",
        b"sy",
        b"sz",
        b"tc",
        b"td",
        b"tf",
        b"tg",
        b"th",
        b"tj",
        b"tk",
        b"tl",
        b"tm",
        b"tn",
        b"to",
        b"tr",
        b"tt",
        b"tv",
        b"tw",
        b"tz",
        b"ua",
        b"ug",
        b"uk",
        b"us",
        b"uy",
        b"uz",
        b"va",
        b"vc",
        b"ve",
        b"vg",
        b"vi",
        b"vn",
        b"vu",
        b"wf",
        b"ws",
        b"ye",
        b"yt",
        b"za",
        b"zm",
        b"zw",
        # Chinsese ICANN TLDs
        b"ren",
        b"shouji",
        b"tushu",
        b"wanggou",
        b"weibo",
        b"xihuan",
        b"xin",
        # French ICANN TLDs
        b"arte",
        b"clinique",
        b"luxe",
        b"maison",
        b"moi",
        b"rsvp",
        b"sarl",
        # German ICANN tlds
        b"epost",
        b"gmbh",
        b"haus",
        b"immobilien",
        b"jetzt",
        b"kaufen",
        b"kinder",
        b"reise",
        b"reisen",
        b"schule",
        b"versicherung",
        # Hindi ICANN tlds
        b"desi",
        b"shiksha",
        # Italian ICANN tlds
        b"casa",
        b"immo",
        b"moda",
        b"voto",
        # Portuguese ICANN tlds
        b"bom",
        b"passagens"
        # Spanish ICANN tlds
        b"abogado",
        b"futbol",
        b"gratis",
        b"hoteles",
        b"juegos",
        b"ltda",
        b"soy",
        b"tienda",
        b"uno",
        b"viajes",
        b"vuelos",
        # International TLDs
        b"xn--11b4c3d",
        b"xn--1ck2e1b",
        b"xn--1qqw23a",
        b"xn--2scrj9c",
        b"xn--30rr7y",
        b"xn--3bst00m",
        b"xn--3ds443g",
        b"xn--3e0b707e",
        b"xn--3hcrj9c",
        b"xn--3pxu8k",
        b"xn--42c2d9a",
        b"xn--45br5cyl",
        b"xn--45brj9c",
        b"xn--45q11c",
        b"xn--4dbrk0ce",
        b"xn--4gbrim",
        b"xn--54b7fta0cc",
        b"xn--55qw42g",
        b"xn--55qx5d",
        b"xn--5su34j936bgsg",
        b"xn--5tzm5g",
        b"xn--6frz82g",
        b"xn--6qq986b3xl",
        b"xn--80adxhks",
        b"xn--80ao21a",
        b"xn--80aqecdr1a",
        b"xn--80asehdb",
        b"xn--80aswg",
        b"xn--8y0a063a",
        b"xn--90a3ac",
        b"xn--90ae",
        b"xn--90ais",
        b"xn--9dbq2a",
        b"xn--9et52u",
        b"xn--9krt00a",
        b"xn--b4w605ferd",
        b"xn--bck1b9a5dre4c",
        b"xn--c1avg",
        b"xn--c2br7g",
        b"xn--cck2b3b",
        b"xn--cckwcxetd",
        b"xn--cg4bki",
        b"xn--clchc0ea0b2g2a9gcd",
        b"xn--czr694b",
        b"xn--czrs0t",
        b"xn--czru2d",
        b"xn--d1acj3b",
        b"xn--d1alf",
        b"xn--e1a4c",
        b"xn--eckvdtc9d",
        b"xn--efvy88h",
        b"xn--fct429k",
        b"xn--fhbei",
        b"xn--fiq228c5hs",
        b"xn--fiq64b",
        b"xn--fiqs8s",
        b"xn--fiqz9s",
        b"xn--fjq720a",
        b"xn--flw351e",
        b"xn--fpcrj9c3d",
        b"xn--fzc2c9e2c",
        b"xn--fzys8d69uvgm",
        b"xn--g2xx48c",
        b"xn--gckr3f0f",
        b"xn--gecrj9c",
        b"xn--gk3at1e",
        b"xn--h2breg3eve",
        b"xn--h2brj9c",
        b"xn--h2brj9c8c",
        b"xn--hxt814e",
        b"xn--i1b6b1a6a2e",
        b"xn--imr513n",
        b"xn--io0a7i",
        b"xn--j1aef",
        b"xn--j1amh",
        b"xn--j6w193g",
        b"xn--jlq480n2rg",
        b"xn--jvr189m",
        b"xn--kcrx77d1x4a",
        b"xn--kprw13d",
        b"xn--kpry57d",
        b"xn--kput3i",
        b"xn--l1acc",
        b"xn--lgbbat1ad8j",
        b"xn--mgb9awbf",
        b"xn--mgba3a3ejt",
        b"xn--mgba3a4f16a",
        b"xn--mgba7c0bbn0a",
        b"xn--mgbaam7a8h",
        b"xn--mgbab2bd",
        b"xn--mgbah1a3hjkrd",
        b"xn--mgbai9azgqp6j",
        b"xn--mgbayh7gpa",
        b"xn--mgbbh1a",
        b"xn--mgbbh1a71e",
        b"xn--mgbc0a9azcg",
        b"xn--mgbca7dzdo",
        b"xn--mgbcpq6gpa1a",
        b"xn--mgberp4a5d4ar",
        b"xn--mgbgu82a",
        b"xn--mgbi4ecexp",
        b"xn--mgbpl2fh",
        b"xn--mgbt3dhd",
        b"xn--mgbtx2b",
        b"xn--mgbx4cd0ab",
        b"xn--mix891f",
        b"xn--mk1bu44c",
        b"xn--mxtq1m",
        b"xn--ngbc5azd",
        b"xn--ngbe9e0a",
        b"xn--ngbrx",
        b"xn--node",
        b"xn--nqv7f",
        b"xn--nqv7fs00ema",
        b"xn--nyqy26a",
        b"xn--o3cw4h",
        b"xn--ogbpf8fl",
        b"xn--otu796d",
        b"xn--p1acf",
        b"xn--p1ai",
        b"xn--pgbs0dh",
        b"xn--pssy2u",
        b"xn--q7ce6a",
        b"xn--q9jyb4c",
        b"xn--qcka1pmc",
        b"xn--qxa6a",
        b"xn--qxam",
        b"xn--rhqv96g",
        b"xn--rovu88b",
        b"xn--rvc1e0am3e",
        b"xn--s9brj9c",
        b"xn--ses554g",
        b"xn--t60b56a",
        b"xn--tckwe",
        b"xn--tiq49xqyj",
        b"xn--unup4y",
        b"xn--vermgensberater-ctb",
        b"xn--vermgensberatung-pwb",
        b"xn--vhquv",
        b"xn--vuq861b",
        b"xn--w4r85el8fhu5dnra",
        b"xn--w4rs40l",
        b"xn--wgbh1c",
        b"xn--wgbl6a",
        b"xn--xhq521b",
        b"xn--xkc2al3hye2a",
        b"xn--xkc2dl3a5ee0h",
        b"xn--y9a3aq",
        b"xn--yfro4i67o",
        b"xn--ygbi2ammx",
        b"xn--zfr164b",
    }
    return bool(
        len(root) < 3  # difficult to register, common variable names
        or root == b"this"  # common variable name in javascript
        or (domain_lower.startswith(b"lib") and tld == b"so")  # ELF false positive
        or (root in root_fpos and tld not in reliable_tlds)  # variable attribute
        or (tld == b"next" and b"iterator" in domain_lower)  # Iterator not domain
        or re.match(b"[a-z]+[.][A-Z][a-z]+", domain)  # attribute access not domain
        or (len(split) == 3 and split[1] == b"prototype" and len(root) < 3 and len(tld) < 3)  # javascript pattern
        or domain_lower.endswith(b"prototype.at")
    )


# Decoders
@decoder
def find_domains(data: bytes) -> list[Node]:
    """Find domains in data"""
    out = []
    for match in re.finditer(DOMAIN_RE, data):
        domain = match.group()
        if not is_domain(domain) or len(domain) < 7:
            continue
        if domain_is_false_positive(domain):
            continue
        out.append(match_to_hit(DOMAIN_TYPE, match))
    return out


@decoder
def find_emails(data: bytes) -> list[Node]:
    """Find email addresses in data"""
    return [match_to_hit(EMAIL_TYPE, match) for match in re.finditer(EMAIL_RE, data) if is_domain(match.group(1))]


@decoder
def find_ips(data: bytes) -> list[Node]:
    """Find ip addresses in data"""
    out = []
    for match in re.finditer(IP_RE, data):
        ip = match.group()
        if not is_ip(ip):
            continue
        if all(byte in b"0x." for byte in ip):
            continue  # 0.0.0.0
        if ip.endswith((b".0", b".255")):
            continue  # Class C network identifier or broadcast address
        start, end = match.span()
        prefix = data[start - 1 :: -1]
        if re.match(rb"\s*>t(?::\w+)?<", prefix):
            continue  # xml section numbering
        if re.match(rb"(?i)\s+(?:noit|[.])ces", prefix):
            continue  # section number
        offset = data.rfind(b"ersion", max(start - 10, 0), start)
        if offset >= 0 and re.match(rb'[\x00=\s"]+$', data[offset + 6 : start]):
            continue  # version number, not an ip address
        out.append(parse_ip(match.group()).shift(match.start()))
    return out


@decoder
def find_urls(data: bytes) -> list[Node]:
    """Find URLs in data"""
    # Todo: blunt hack to approximate context
    # need to do actual context aware search
    contexts = {
        ord("'"): ord("'"),
        ord("("): ord(")"),
    }
    out = []
    for match in re.finditer(URL_RE, data):
        group = match.group()
        start, end = match.span()
        prev = data[start - 1]
        if start == 0:
            pass  # No context
        elif group[prev : prev + 1] == b"0" and not _is_printable(data[start - 10 : start]):
            # Pascal string in PE file
            end = start + prev
            group = group[:prev]
        elif prev in contexts:
            close = group.find(contexts[prev])
            if close > -1:
                end = start + close
                group = group[:close]
        if not is_url(group):
            continue
        out.append(
            Node(
                URL_TYPE,
                *normalize_percent_encoding(group),
                start,
                end,
                children=parse_url(group),
            )
        )
    return out


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
    """Parses a url into a decoding tree.

    The url is separated into parts:
    - scheme
    - username
    - password
    - host (ip or domain)
    - path
    - query
    - fragment
    Each part is decoded and added as a child if it is present in the url.

    This function should only be used if a decoding tree is necessary.
    The standard library urllib.path.urlsplit is prefered if separating a url
    into subparts is all that is required. If splitting and decoding is required,
    consider using urlsplit then unquote_to_bytes to remove percent encoding
    and one of the host specific parsers (parse_ip, parse_ipv6) if necessary.
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
                (
                    MIXED_CASE_OBF
                    # url.scheme is normalized by urlsplit
                    if url_text[0 : len(url.scheme)] not in (url.scheme, url.scheme.upper())
                    else ""
                ),
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


def _is_printable(b: bytes) -> bool:
    try:
        return b.decode("ascii").isprintable()
    except UnicodeDecodeError:
        return False
