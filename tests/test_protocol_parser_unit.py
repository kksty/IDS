from app.services.protocol_parser import parse_packet_for_protocol


def _dns_query(domain: str = "example.com") -> bytes:
    # Minimal DNS query: header(12) + QNAME + QTYPE + QCLASS
    # ID=0x1234, flags=0x0100, QDCOUNT=1
    header = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    labels = domain.split(".")
    qname = b"".join([bytes([len(l)]) + l.encode() for l in labels]) + b"\x00"
    qtype = (1).to_bytes(2, "big")  # A
    qclass = (1).to_bytes(2, "big")  # IN
    return header + qname + qtype + qclass


def test_detect_http_by_payload_prefix():
    payload = b"GET /index HTTP/1.1\r\nHost: x\r\n\r\n"
    parsed = parse_packet_for_protocol("1.1.1.1", "2.2.2.2", 12345, 80, payload, "TCP")
    assert parsed is not None
    assert parsed.protocol == "http"


def test_detect_dns_by_port_and_parse_domain_and_type():
    payload = _dns_query("a.example.com")
    parsed = parse_packet_for_protocol("1.1.1.1", "8.8.8.8", 5353, 53, payload, "UDP")
    assert parsed is not None
    assert parsed.protocol == "dns"
    assert parsed.parsed_data.get("domain") == "a.example.com"
    assert parsed.parsed_data.get("record_type") == "A"


def test_non_tcp_udp_only_port_detection():
    # ICMP payload should not be treated as HTTP by payload; only port detection applies.
    payload = b"GET / HTTP/1.1\r\n\r\n"
    parsed = parse_packet_for_protocol("1.1.1.1", "2.2.2.2", 123, 22, payload, "ICMP")
    assert parsed is not None
    assert parsed.protocol == "ssh"


def test_unknown_protocol_returns_none():
    # Keep payload < 12 bytes to avoid the simplified DNS heuristic.
    payload = b"xyz"
    parsed = parse_packet_for_protocol("1.1.1.1", "2.2.2.2", 1111, 2222, payload, "TCP")
    assert parsed is None
