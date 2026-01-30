from __future__ import annotations

from typing import List, Tuple, Dict, Any
import zlib

_HAVE_HTTPT = False
try:
    import httptools  # type: ignore
    _HAVE_HTTPT = True
except Exception:
    _HAVE_HTTPT = False

_HAVE_PCAPKIT = False
try:
    import pcapkit  # type: ignore
    _HAVE_PCAPKIT = True
except Exception:
    _HAVE_PCAPKIT = False


class HttpRequestParser:
    def __init__(self):
        self.requests: List[Dict[str, Any]] = []
        self.headers = {}
        self.method = ""
        self.path = ""
        self.version = ""
        self.body_buffer = bytearray()
        self.parser = None

    def on_method(self, method: bytes):
        pass  # httptools doesn't call this

    def on_url(self, url: bytes):
        pass  # httptools doesn't call this

    def on_header(self, name: bytes, value: bytes):
        pass  # httptools doesn't call this

    def on_headers_complete(self):
        pass

    def on_body(self, body: bytes):
        self.body_buffer.extend(body)

    def on_message_complete(self):
        # Get data from parser
        self.method = self.parser.get_method().decode("utf-8", errors="ignore")
        self.path = self.parser.get_url().decode("utf-8", errors="ignore")
        self.version = f"HTTP/{self.parser.get_http_version()}"
        self.headers = {k.decode("utf-8", errors="ignore"): v.decode("utf-8", errors="ignore") for k, v in self.parser.get_headers()}

        body = bytes(self.body_buffer)
        
        # Check if body is complete
        content_length = 0
        if "content-length" in self.headers:
            try:
                content_length = int(self.headers["content-length"])
            except Exception:
                content_length = 0
        
        if len(body) < content_length:
            # Body incomplete, don't add request
            return
        
        # Decode if needed
        try:
            ce = self.headers.get("content-encoding", "").lower()
            if "gzip" in ce or "deflate" in ce:
                body = _decode_gzip(body)
        except Exception:
            pass

        raw = f"{self.method} {self.path} {self.version}\r\n".encode() + b"\r\n".join([f"{k}: {v}".encode() for k, v in self.headers.items()]) + b"\r\n\r\n" + body

        self.requests.append({
            "method": self.method,
            "path": self.path,
            "version": self.version,
            "headers": self.headers,
            "body": body,
            "raw": raw,
        })
        # Reset for next request
        self.headers = {}
        self.method = ""
        self.path = ""
        self.version = ""
        self.body_buffer = bytearray()


def extract_http_requests(buf: bytes) -> Tuple[List[Dict[str, Any]], int]:
    """Extract HTTP requests from buffer using httptools if available, else fallback."""
    if _HAVE_HTTPT:
        return _extract_http_requests_httptools(buf)
    else:
        return _extract_http_requests_fallback(buf)


def _extract_http_requests_httptools(buf: bytes) -> Tuple[List[Dict[str, Any]], int]:
    """Extract HTTP requests using httptools."""
    parser_obj = HttpRequestParser()
    parser = httptools.HttpRequestParser(parser_obj)
    parser_obj.parser = parser  # Set reference for callbacks
    try:
        parser.feed_data(buf)
        # If no requests were parsed (e.g., incomplete body), return 0 consumed
        if not parser_obj.requests:
            return [], 0
        return parser_obj.requests, len(buf)  # Assume all data consumed for simplicity
    except Exception:
        # If httptools fails, fallback
        return _extract_http_requests_fallback(buf)


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
