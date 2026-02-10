import re

from app.services.engine import _match_content_patterns, _pcre_matches


def test_match_content_patterns_simple_and():
    payload = b"xxAAyyBBzz"
    md = {"content_patterns": ["AA", "BB"]}
    assert _match_content_patterns(payload, md) is True


def test_match_content_patterns_distance_and_within():
    payload = b"AAxxBB"
    md = {
        "content_patterns": ["AA", "BB"],
        "content_options": [{}, {"distance": 2, "within": 2}],
    }
    assert _match_content_patterns(payload, md) is True


def test_match_content_patterns_within_fail_when_too_far():
    payload = b"AAxxxxBB"
    md = {
        "content_patterns": ["AA", "BB"],
        "content_options": [{}, {"within": 2}],
    }
    assert _match_content_patterns(payload, md) is False


def test_match_content_patterns_offset_and_depth_first_pattern():
    payload = b"zzAAzz"
    md = {
        "content_patterns": ["AA"],
        "content_options": [{"offset": 2, "depth": 2}],
    }
    assert _match_content_patterns(payload, md) is True


def test_match_content_patterns_legacy_top_level_options_apply_to_first():
    payload = b"zzAAzz"
    md = {
        "content_patterns": ["AA"],
        "offset": 2,
        "depth": 2,
    }
    assert _match_content_patterns(payload, md) is True


def test_match_content_patterns_nocase_option():
    payload = b"xxaBxx"
    md = {
        "content_patterns": ["Ab"],
        "content_options": [{"nocase": True}],
    }
    assert _match_content_patterns(payload, md) is True


def test_pcre_matches_and_semantics():
    rx1 = re.compile(r"a")
    rx2 = re.compile(r"b")
    assert _pcre_matches(b"ab", [rx1, rx2]) is True
    assert _pcre_matches(b"a", [rx1, rx2]) is False
