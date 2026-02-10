# -*- coding: utf-8 -*-
from __future__ import annotations

from typing import List, Tuple, Dict, Any, Optional
import zlib

_HAVE_HTTPT = False
try:
    import httptools  # type: ignore
    _HAVE_HTTPT = True
except Exception:
    _HAVE_HTTPT = False

# pcapkit 不用于 HTTP 解析：它的应用层自动解析在遇到半包/非 HTTP 数据时容易产生噪声报错。
# HTTP 解析统一由 httptools（若可用）完成。
_HAVE_PCAPKIT = False


class HttpRequestParser:
    """httptools 的回调接收器。

    说明：httptools 通过回调提供 method/url/headers/body 等字段。
    这里把一次 message 的数据收集为 dict 并 append 到 requests。
    """

    def __init__(self):
        self.requests: List[Dict[str, Any]] = []
        self._reset_message()

    def _reset_message(self) -> None:
        self.headers: Dict[str, str] = {}
        self.method: str = ""
        self.path: str = ""
        self.version: str = ""
        self.body_buffer = bytearray()

    def on_message_begin(self):
        self._reset_message()

    def on_url(self, url: bytes):
        try:
            self.path = url.decode("utf-8", errors="ignore")
        except Exception:
            self.path = ""

    def on_header(self, name: bytes, value: bytes):
        try:
            k = name.decode("utf-8", errors="ignore").strip().lower()
            v = value.decode("utf-8", errors="ignore").strip()
            if k:
                self.headers[k] = v
        except Exception:
            pass

    def on_headers_complete(self):
        # method / version 需要从 parser 对象上取，extract_http_requests_httptools 里会注入 self._parser
        try:
            self.method = self._parser.get_method().decode("utf-8", errors="ignore")  # type: ignore[attr-defined]
        except Exception:
            self.method = ""
        try:
            self.version = f"HTTP/{self._parser.get_http_version()}"  # type: ignore[attr-defined]
        except Exception:
            self.version = ""

    def on_body(self, body: bytes):
        self.body_buffer.extend(body)

    def on_message_complete(self):
        body = bytes(self.body_buffer)

        # 解压（尽量而为；失败就返回原始 body）
        try:
            ce = (self.headers.get("content-encoding") or "").lower()
            if "gzip" in ce or "deflate" in ce:
                body = _decode_gzip(body)
        except Exception:
            pass

        # 生成 raw（用于去重/展示；不追求完全还原）
        try:
            header_lines = [f"{k}: {v}".encode() for k, v in self.headers.items()]
            raw = f"{self.method} {self.path} {self.version}\r\n".encode() + b"\r\n".join(header_lines) + b"\r\n\r\n" + body
        except Exception:
            raw = body

        self.requests.append({
            "method": self.method,
            "path": self.path,
            "version": self.version,
            "headers": dict(self.headers),
            "body": body,
            "raw": raw,
        })


class HttpResponseParser:
    """httptools 的响应回调接收器。"""

    def __init__(self):
        self.responses: List[Dict[str, Any]] = []
        self._reset_message()

    def _reset_message(self) -> None:
        self.headers: Dict[str, str] = {}
        self.status_text: str = ""
        self.status_code: Optional[int] = None
        self.version: str = ""
        self.body_buffer = bytearray()

    def on_message_begin(self):
        self._reset_message()

    def on_status(self, status: bytes):
        try:
            self.status_text = status.decode("utf-8", errors="ignore")
        except Exception:
            self.status_text = ""

    def on_header(self, name: bytes, value: bytes):
        try:
            k = name.decode("utf-8", errors="ignore").strip().lower()
            v = value.decode("utf-8", errors="ignore").strip()
            if k:
                self.headers[k] = v
        except Exception:
            pass

    def on_headers_complete(self):
        try:
            self.version = f"HTTP/{self._parser.get_http_version()}"  # type: ignore[attr-defined]
        except Exception:
            self.version = ""
        try:
            self.status_code = int(self._parser.get_status_code())  # type: ignore[attr-defined]
        except Exception:
            self.status_code = None

    def on_body(self, body: bytes):
        self.body_buffer.extend(body)

    def on_message_complete(self):
        body = bytes(self.body_buffer)

        try:
            ce = (self.headers.get("content-encoding") or "").lower()
            if "gzip" in ce or "deflate" in ce:
                body = _decode_gzip(body)
        except Exception:
            pass

        try:
            status_code = "" if self.status_code is None else str(self.status_code)
            status_line = f"{self.version} {status_code} {self.status_text}".strip().encode()
            header_lines = [f"{k}: {v}".encode() for k, v in self.headers.items()]
            raw = status_line + b"\r\n" + b"\r\n".join(header_lines) + b"\r\n\r\n" + body
        except Exception:
            raw = body

        self.responses.append({
            "version": self.version,
            "status_code": self.status_code,
            "status_text": self.status_text,
            "headers": dict(self.headers),
            "body": body,
            "raw": raw,
        })


def extract_http_requests(buf: bytes) -> Tuple[List[Dict[str, Any]], int]:
    """Extract HTTP requests from buffer using httptools if available, else fallback."""
    if _HAVE_HTTPT:
        return _extract_http_requests_httptools(buf)
    else:
        return _extract_http_requests_fallback(buf)


def extract_http_responses(buf: bytes) -> Tuple[List[Dict[str, Any]], int]:
    """Extract HTTP responses from buffer using httptools if available, else fallback."""
    if _HAVE_HTTPT:
        return _extract_http_responses_httptools(buf)
    else:
        return _extract_http_responses_fallback(buf)


def _extract_http_requests_httptools(buf: bytes) -> Tuple[List[Dict[str, Any]], int]:
    """Extract HTTP requests using httptools.

    注意：httptools 适用于“连续的 HTTP 字节流”。TCP 半包/乱序需要上层先重组。

    consumed 的语义：为了保持现有调用方式，这里仍然返回“消费了多少输入字节”。
    httptools 不直接暴露精确消费位置，因此：
    - 如果解析出至少一个完整 request，则认为本次 buf 都可消费（上层按现有逻辑清理 buffer）
    - 如果没有完整 request，则返回 0（让上层继续累积）
    """
    parser_obj = HttpRequestParser()
    parser = httptools.HttpRequestParser(parser_obj)
    # 注入 parser 引用供回调取 method/version
    parser_obj._parser = parser  # type: ignore[attr-defined]

    try:
        parser.feed_data(buf)
    except Exception:
        # httptools 在遇到非 HTTP 或明显损坏数据时可能抛异常；回退到 fallback
        return _extract_http_requests_fallback(buf)

    if not parser_obj.requests:
        return [], 0

    return parser_obj.requests, len(buf)


def _extract_http_responses_httptools(buf: bytes) -> Tuple[List[Dict[str, Any]], int]:
    parser_obj = HttpResponseParser()
    parser = httptools.HttpResponseParser(parser_obj)
    parser_obj._parser = parser  # type: ignore[attr-defined]

    try:
        parser.feed_data(buf)
    except Exception:
        return _extract_http_responses_fallback(buf)

    if not parser_obj.responses:
        return [], 0

    return parser_obj.responses, len(buf)


def _extract_http_requests_fallback(buf: bytes) -> Tuple[List[Dict[str, Any]], int]:
    """Fallback implementation."""
    requests: List[Dict[str, Any]] = []
    i = 0
    total = len(buf)
    while True:
        if i >= total:
            break
        # 找到 header 结束标记\r\n\r\n
        header_end = buf.find(b"\r\n\r\n", i)
        if header_end == -1:
            break
        header_block = buf[i:header_end]
        # 第一行
        lines = header_block.split(b"\r\n")
        if len(lines) == 0:
            # malformed
            i = header_end + 4
            continue
        request_line = lines[0].decode("utf-8", errors="ignore")
        parts = request_line.split(" ")
        if len(parts) < 3:
            # malformed line, skip
            i = header_end + 4
            continue
        # Distinguish request vs response: responses start with HTTP/ (e.g. "HTTP/1.1 200 OK").
        if parts[0].upper().startswith("HTTP/"):
            # This is an HTTP response; consume it but do not return as a request
            # compute content-length if present and advance
            method = None
            path = None
            version = parts[0]
        else:
            method, path, version = parts[0], parts[1], parts[2]
        headers = _parse_headers(header_block)
        content_length = 0
        if "content-length" in headers:
            try:
                content_length = int(headers["content-length"])
            except Exception:
                content_length = 0

        req_total_end = header_end + 4 + content_length
        if total < req_total_end:
            # body not complete yet
            break

        body = buf[header_end + 4:req_total_end]
        raw = buf[i:req_total_end]
        # Only append if this is a request (method != None)
        if method is not None:
            # attempt to decode chunked/gzip body if headers indicate
            try:
                te = headers.get("transfer-encoding", "").lower()
                if "chunked" in te:
                    body = _decode_chunked(body)
            except Exception:
                pass
            try:
                ce = headers.get("content-encoding", "").lower()
                if "gzip" in ce or "deflate" in ce:
                    body = _decode_gzip(body)
            except Exception:
                pass

            requests.append({
                "method": method,
                "path": path,
                "version": version,
                "headers": headers,
                "body": body,
                "raw": raw,
            })
        i = req_total_end

    return requests, i


def _extract_http_responses_fallback(buf: bytes) -> Tuple[List[Dict[str, Any]], int]:
    responses: List[Dict[str, Any]] = []
    i = 0
    total = len(buf)
    while True:
        if i >= total:
            break
        header_end = buf.find(b"\r\n\r\n", i)
        if header_end == -1:
            break
        header_block = buf[i:header_end]
        lines = header_block.split(b"\r\n")
        if not lines:
            i = header_end + 4
            continue
        status_line = lines[0].decode("utf-8", errors="ignore")
        parts = status_line.split(" ")
        if len(parts) < 2 or not parts[0].upper().startswith("HTTP/"):
            i = header_end + 4
            continue

        version = parts[0]
        status_code = None
        try:
            status_code = int(parts[1])
        except Exception:
            status_code = None
        status_text = " ".join(parts[2:]) if len(parts) > 2 else ""

        headers = _parse_headers(header_block)
        content_length = 0
        if "content-length" in headers:
            try:
                content_length = int(headers["content-length"])
            except Exception:
                content_length = 0

        resp_total_end = header_end + 4 + content_length
        if total < resp_total_end:
            break

        body = buf[header_end + 4:resp_total_end]
        raw = buf[i:resp_total_end]
        responses.append({
            "version": version,
            "status_code": status_code,
            "status_text": status_text,
            "headers": headers,
            "body": body,
            "raw": raw,
        })
        i = resp_total_end

    return responses, i


def _parse_headers(header_bytes: bytes) -> Dict[str, str]:
    headers: Dict[str, str] = {}
    lines = header_bytes.split(b"\r\n")
    for line in lines[1:]:
        if not line:
            continue
        parts = line.split(b":", 1)
        if len(parts) == 2:
            k = parts[0].decode("utf-8", errors="ignore").strip()
            v = parts[1].decode("utf-8", errors="ignore").strip()
            headers[k.lower()] = v
    return headers


def _decode_chunked(b: bytes) -> bytes:
    """Decodes HTTP chunked transfer encoding (simple implementation)."""
    out = bytearray()
    i = 0
    L = len(b)
    while i < L:
        # read chunk size line
        j = b.find(b"\r\n", i)
        if j == -1:
            break
        try:
            size = int(b[i:j].split(b";")[0].strip(), 16)
        except Exception:
            break
        i = j + 2
        if size == 0:
            # consume trailing CRLF
            i = b.find(b"\r\n", i)
            if i == -1:
                i = L
            break
        if i + size > L:
            # incomplete
            break
        out += b[i : i + size]
        i = i + size + 2  # skip CRLF after chunk
    return bytes(out)


def _decode_gzip(b: bytes) -> bytes:
    try:
        import gzip
        return gzip.decompress(b)
    except Exception:
        try:
            # try zlib raw inflate
            return zlib.decompress(b)
        except Exception:
            return b
