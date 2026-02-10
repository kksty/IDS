import re

from app.services.aho import _compile_pcre, _normalize_snort_content_for_match


def test_normalize_snort_content_plain_text():
    assert _normalize_snort_content_for_match("abc") == "abc"


def test_normalize_snort_content_hex_block():
    assert _normalize_snort_content_for_match("|41 42 43|") == "ABC"


def test_normalize_snort_content_mixed_hex_and_text():
    # |41| == 'A'
    assert _normalize_snort_content_for_match("|41|BC|44|") == "ABCD"


def test_normalize_snort_content_x_escapes():
    assert _normalize_snort_content_for_match("\\x41\\x42") == "AB"


def test_compile_pcre_snort_slashes_and_i_flag():
    rx = _compile_pcre(r"/(exe|dll|scr)$/i")
    assert rx is not None
    assert rx.search("a.EXE") is not None
    assert rx.search("a.txt") is None


def test_compile_pcre_plain_regex():
    rx = _compile_pcre(r"a+b")
    assert isinstance(rx, re.Pattern)
    assert rx.search("aaab") is not None
