from multidecoder.analyzers.chr import find_chr


def test_find_chr_empty():
    assert find_chr(b'') == []


def test_find_chr_a():
    assert find_chr(b'chr(65)')[0].value == b'A'
    assert find_chr(b'chrw(65)')[0].value == b'A'
    assert find_chr(b'chrb(65)')[0].value == b'A'


def test_find_chr_duck():
    assert find_chr(b'chr(69)chr(117)chr(99)chr(107)')
