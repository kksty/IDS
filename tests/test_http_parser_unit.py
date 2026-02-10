import zlib

import pytest

from app.services import http_parser as hp


def test_decode_chunked_basic():
    raw = b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n"
    assert hp._decode_chunked(raw) == b"Wikipedia"


def test_decode_chunked_with_extensions():
    raw = b"4;ext=1\r\nWiki\r\n0\r\n\r\n"
    assert hp._decode_chunked(raw) == b"Wiki"


def test_decode_gzip_roundtrip():
    payload = b"hello gzip"
    gz = zlib.compress(payload)
    assert hp._decode_gzip(gz) == payload


def test_extract_http_requests_fallback_get_consumed():
    buf = b"GET /path?x=1 HTTP/1.1\r\nHost: example.com\r\n\r\n"
    reqs, consumed = hp._extract_http_requests_fallback(buf)
    assert consumed == len(buf)
    assert len(reqs) == 1
    assert reqs[0]["method"] == "GET"
    assert reqs[0]["path"] == "/path?x=1"


def test_extract_http_requests_fallback_post_with_length():
    body = b"password=1234"
    buf = (
        b"POST /login HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        + b"Content-Length: "
        + str(len(body)).encode()
        + b"\r\n\r\n"
        + body
    )
    reqs, consumed = hp._extract_http_requests_fallback(buf)
    assert consumed == len(buf)
    assert len(reqs) == 1
    assert reqs[0]["method"] == "POST"
    assert reqs[0]["path"] == "/login"
    assert reqs[0]["body"] == body


def test_extract_http_requests_fallback_partial_body_not_consumed():
    body = b"abcde"
    buf = (
        b"POST /login HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        + b"Content-Length: 10\r\n\r\n"
        + body
    )
    reqs, consumed = hp._extract_http_requests_fallback(buf)
    assert reqs == []
    assert consumed == 0


def test_extract_http_requests_httptools_exception_falls_back(monkeypatch):
    class _BadParser:
        def __init__(self, *_a, **_kw):
            pass

        def feed_data(self, _buf):
            raise RuntimeError("boom")

    class _BadHttpTools:
        HttpRequestParser = _BadParser

    monkeypatch.setattr(hp, "_HAVE_HTTPT", True)
    monkeypatch.setattr(hp, "httptools", _BadHttpTools())

    buf = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    reqs, consumed = hp.extract_http_requests(buf)
    assert consumed == len(buf)
    assert len(reqs) == 1


def test_extract_http_responses_fallback_simple():
    buf = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHello"
    resps, consumed = hp._extract_http_responses_fallback(buf)
    assert consumed == len(buf)
    assert len(resps) == 1
    r = resps[0]
    assert r["status_code"] == 200
    assert r["body"] == b"Hello"


@pytest.mark.parametrize(
    "buf",
    [
        b"",  # empty
        b"NOTHTTP",  # not a request
        b"GET / HTTP/1.1\r\nHost: x\r\n",  # missing header end
    ],
)
def test_extract_http_requests_fallback_non_message(buf):
    reqs, consumed = hp._extract_http_requests_fallback(buf)
    assert reqs == []
    assert consumed == 0
