import pytest

from app.services.http_parser import extract_http_requests


def test_extract_simple_get():
    buf = b"GET /path?query=1 HTTP/1.1\r\nHost: example.com\r\n\r\n"
    reqs, consumed = extract_http_requests(buf)
    assert consumed == len(buf)
    assert len(reqs) == 1
    r = reqs[0]
    assert r["method"] == "GET"
    assert r["path"] == "/path?query=1"
    assert r["body"] == b""


def test_extract_post_with_length():
    body = b"password=1234"
    buf = b"POST /login HTTP/1.1\r\nHost: example.com\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
    reqs, consumed = extract_http_requests(buf)
    assert consumed == len(buf)
    assert len(reqs) == 1
    r = reqs[0]
    assert r["method"] == "POST"
    assert r["path"] == "/login"
    assert r["body"] == body


def test_partial_request_not_consumed():
    # header present but body incomplete
    body = b"password=1234"
    header = b"POST /login HTTP/1.1\r\nHost: example.com\r\nContent-Length: " + str(len(body)+10).encode() + b"\r\n\r\n"
    buf = header + body[:5]
    reqs, consumed = extract_http_requests(buf)
    assert consumed == 0
    assert len(reqs) == 0
