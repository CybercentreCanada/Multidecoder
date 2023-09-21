import re

from multidecoder.decoders.xml import XML_ESCAPE_RE, find_xml_hex, unescape_xml
from multidecoder.node import Node

external = b'TargetMode="&#x45;&#x78;&#x74;&#x65;&#x72;&#x6e;&#x61;&#x6c;"'


def test_re_empty():
    assert not re.search(XML_ESCAPE_RE, b"")


def test_re_external():
    match = re.search(XML_ESCAPE_RE, external)
    assert match
    assert external[match.start() : match.end()] == b"&#x45;&#x78;&#x74;&#x65;&#x72;&#x6e;&#x61;&#x6c;"


def test_unescape_external():
    assert unescape_xml(b"&#x45;&#x78;&#x74;&#x65;&#x72;&#x6e;&#x61;&#x6c;") == b"External"


def test_find_external():
    assert find_xml_hex(external) == [Node("", b"External", "unescape.xml", 12, 60)]
