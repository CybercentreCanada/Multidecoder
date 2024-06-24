from multidecoder.decoders.reverse import find_reverse


def test_find_strreverse_empty():
    assert find_reverse(b"") == []


def test_find_strreverse_duck():
    assert find_reverse(b'StrReverse("kcud")')[0].value == b"duck"


def test_find_strreverse_endpoints():
    string = b'Reverse("kcud")'
    hit = find_reverse(string)[0]
    assert hit.start == 0
    assert hit.end == len(string)
