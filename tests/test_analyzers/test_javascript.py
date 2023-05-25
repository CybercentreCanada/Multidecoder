from multidecoder.analyzers.javascript import find_unescape
from multidecoder.hit import Hit


def test_find_unescape():
    assert find_unescape(b"unescape('help%20Im%20stuck%20in%20a%20url%20factory!')") == [Hit(b'help Im stuck in a url factory!', 'function.unescape', 0, 55)]
