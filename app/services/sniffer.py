import datetime
import asyncio
from typing import Optional, Callable, Coroutine, Any
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
import logging

from app.services.detection import ContextManager
from app.services.http_parser import extract_http_requests
from app.services.reassembly_adapter import FlowReassemblerManager
from app.services.behavior_analyzer import BehaviorAnalyzer
from app.services.protocol_parser import parse_packet_for_protocol

# 单例式上下文管理器（嗅探线程使用）
_CTX_MGR = ContextManager(timeout=300.0)
_REASM_MGR = FlowReassemblerManager(max_buffer=256 * 1024)
_BEHAVIOR_ANALYZER = BehaviorAnalyzer()

logger = logging.getLogger("ids.sniffer")

# Import pypcapkit for packet parsing
try:
    from pcapkit.protocols.internet import IPv4
    from pcapkit.protocols.transport import TCP as PcapTCP, UDP as PcapUDP
    _HAVE_PCAPKIT = True
except ImportError:
    _HAVE_PCAPKIT = False

# Statistics for pypcapkit parsing
_pypcapkit_stats = {"success": 0, "failure": 0}


def _get_default_broadcast_callable() -> Callable[[dict], Coroutine[Any, Any, Any]]:
    # 延迟导入，避免循环依赖；返回一个可调用对象（调用后返回 coroutine）
    from app.routers.websocket import manager
    return manager.broadcast


def _packet_callback_factory(loop: asyncio.AbstractEventLoop, broadcast_callable: Callable[[dict], Coroutine[Any, Any, Any]]):
    def _packet_callback(packet):
        if IP in packet:
            ip_layer = packet[IP]

            proto = "IP"
            if packet.haslayer(TCP):
                proto = "TCP"
            elif packet.haslayer(UDP):
                proto = "UDP"

            sport = getattr(packet, "sport", "")
            # 尝试提取应用层 payload：优先使用 Raw 层（仅负载），避免包含 TCP/UDP 头部字节
            payload = b""
            try:
                from scapy.packet import Raw

                if packet.haslayer(Raw):
                    payload = bytes(packet.getlayer(Raw).load)
                elif packet.haslayer(TCP):
                    # bytes(TCP.payload) 在某些 scapy 版本会包含层序列化的头部，
                    # 但通常 packet[TCP].payload.raw_packet_cache 或 .load 可用；
                    # 这里安全取 bytes(packet[TCP].payload)
                    try:
                        payload = bytes(packet[TCP].payload)
                    except Exception:
                        payload = b""
                elif packet.haslayer(UDP):
                    try:
                        payload = bytes(packet[UDP].payload)
                    except Exception:
                        payload = b""
                else:
                    # fallback to ip payload bytes
                    try:
                        payload = bytes(ip_layer.payload)
                    except Exception:
                        payload = b""
            except Exception:
                # final fallback
                try:
                    payload = bytes(packet.payload)
                except Exception:
                    payload = b""

            # Try to parse with pypcapkit for more accurate information
            if _HAVE_PCAPKIT:
                try:
                    # Use IP layer bytes instead of full packet bytes
                    ip_bytes = bytes(ip_layer)
                    pcap_ip = IPv4(ip_bytes)
                    src_ip = str(pcap_ip.src)
                    dst_ip = str(pcap_ip.dst)

                    if isinstance(pcap_ip.payload, PcapTCP):
                        proto = "TCP"
                        tcp_info = pcap_ip.payload.info
                        sport = int(tcp_info.srcport)
                        dport = int(tcp_info.dstport)
                        # Get payload from pypcapkit
                        if hasattr(pcap_ip.payload.payload, 'data'):
                            payload = pcap_ip.payload.payload.data
                    elif isinstance(pcap_ip.payload, PcapUDP):
                        proto = "UDP"
                        udp_info = pcap_ip.payload.info
                        sport = int(udp_info.srcport)
                        dport = int(udp_info.dstport)
                        # Get payload from pypcapkit
                        if hasattr(pcap_ip.payload.payload, 'data'):
                            payload = pcap_ip.payload.payload.data
                    else:
                        src_ip = ip_layer.src
                        dst_ip = ip_layer.dst
                        sport = getattr(packet, "sport", "")
                        dport = getattr(packet, "dport", "")

                    _pypcapkit_stats["success"] += 1

                except Exception as e:
                    _pypcapkit_stats["failure"] += 1
                    # Only log at debug level and occasionally to avoid spam
                    if logger.isEnabledFor(logging.DEBUG) and _pypcapkit_stats["failure"] % 100 == 0:
                        total = _pypcapkit_stats["success"] + _pypcapkit_stats["failure"]
                        success_rate = (_pypcapkit_stats["success"] / total * 100) if total > 0 else 0
                        logger.debug(f"Failed to parse with pypcapkit: {e}, falling back to scapy. "
                                   f"Success rate: {success_rate:.1f}% ({_pypcapkit_stats['success']}/{total})")
                    src_ip = ip_layer.src
                    dst_ip = ip_layer.dst
                    sport = getattr(packet, "sport", "")
                    dport = getattr(packet, "dport", "")
            else:
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst
                sport = getattr(packet, "sport", "")
                dport = getattr(packet, "dport", "")
            if proto == "TCP":
                # extract seq if available
                seq = None
                try:
                    seq = int(packet[TCP].seq)
                except Exception:
                    seq = None

                # 行为分析：记录连接信息
                _BEHAVIOR_ANALYZER.track_connection(src_ip, dst_ip, sport, dport, proto)

                # maintain lightweight context for metadata and recent hashes
                ctx = _CTX_MGR.append_to_flow("TCP", src_ip, dst_ip, b"", sport=sport, dport=dport)

                # feed reassembly manager; if seq missing, fall back to append-bytes
                ready = b""
                if seq is not None:
                    ready = _REASM_MGR.append("TCP", src_ip, dst_ip, seq, payload, sport=sport, dport=dport)
                else:
                    # best-effort: append raw payload to context buffer and attempt HTTP extraction
                    ctx.append(payload)
                    ready = ctx.get_buffer()

                if ready:
                    # 尝试提取 HTTP 请求
                    requests, consumed = extract_http_requests(ready)
                    if consumed:
                        # 如果来自本地 ctx.buffer（fallback），移除已消费字节
                        try:
                            if seq is None:
                                del ctx.buffer[:consumed]
                        except Exception:
                            ctx.clear()

                    # 对每个完整请求做匹配（只匹配请求方向，忽略 response）
                    for req in requests:
                        # 对提取的请求原始字节计算一个短哈希值以避免处理两次提取相同的请求（如lo重复捕获等）
                        try:
                            import hashlib
                            raw_bytes = req.get("raw", b"") or b""
                            req_hash = hashlib.sha1(raw_bytes).hexdigest()
                        except Exception:
                            req_hash = None

                        # cleanup old hashes and check recent
                        try:
                            seen_hashes = ctx.meta.setdefault("recent_req_hashes", {})
                            now_ts = time.time()
                            # remove entries older than 2s
                            for k, t in list(seen_hashes.items()):
                                if now_ts - t > 2.0:
                                    del seen_hashes[k]
                            if req_hash is not None and req_hash in seen_hashes:
                                continue
                            if req_hash is not None:
                                seen_hashes[req_hash] = now_ts
                        except Exception:
                            pass
                        # 把 path 与 body 一并作为匹配载体
                        try:
                            match_payload_src = req.get("path", "").encode("utf-8", errors="ignore") + b" " + req.get("body", b"")
                        except Exception:
                            match_payload_src = req.get("raw", b"")

                        from app.services.engine import match_payload
                        from app.services.alerter import get_alerter
                        from app.metrics import MATCHES_FOUND, PACKETS_PROCESSED

                        PACKETS_PROCESSED.inc()

                        # 仅当解析到 method（即为请求）且 method 看起来是常见的 HTTP 方法时才匹配
                        method = (req.get("method") or "").upper()
                        if method not in ("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"): 
                            continue

                        matches = match_payload(match_payload_src, "TCP", str(dport), src_ip, str(sport), dst_ip)
                        if matches:
                            try:
                                MATCHES_FOUND.inc(len(matches))
                            except Exception:
                                pass
                            alerter = get_alerter(broadcast_callable, loop)
                            # per-extraction local tracking to avoid emitting duplicate alerts for identical matches
                            # within the same extracted HTTP request. Do not persist across requests.
                            try:
                                body_snip = (req.get("body") or b"")[:64]
                            except Exception:
                                body_snip = b""
                            req_ident = f"{(req.get('method') or '').upper()} {req.get('path') or ''} {body_snip!r}"
                            sent_local = set()
                            # 去重：同一次检测按 rule_id 只发送一条即时告警（避免同一规则多模式导致重复）
                            seen = set()
                        for m in matches:
                            rid = m.get("rule_id")
                            if rid in seen:
                                continue
                            seen.add(rid)
                            sent_key = (rid, req_ident)
                            if sent_key in sent_local:
                                continue
                            sent_local.add(sent_key)
                            # match found
                            # 只把匹配片段与简短上下文（method+path）作为 preview
                            packet_summary = f"HTTP {src_ip}:{sport} -> {dst_ip} {req.get('method')} {req.get('path')}"
                            alert_data = {
                                "timestamp": datetime.datetime.now().strftime("%H:%M:%S"),
                                "protocol": proto,
                                "src_ip": src_ip,
                                "dst_ip": dst_ip,
                                "packet_summary": packet_summary,
                                "match_rule": rid,
                                "match_text": m.get("match"),
                                "match_type": m.get("type"),
                                # payload_preview 用于 DB/前端短摘要，优先显示 URL 而不是完整报文
                                "payload_preview": req.get('path') or packet_summary,
                            }
                            try:
                                alerter.handle_alert(alert_data)
                            except Exception:
                                logger.exception("[!] Alerter failed to handle alert")

                # done processing HTTP requests for this packet
                return

            # 行为分析：记录连接信息（TCP和UDP都处理）
            _BEHAVIOR_ANALYZER.track_connection(src_ip, dst_ip, sport, dport, proto)

            # 协议解析：尝试解析特定协议的内容
            parsed_protocol = parse_packet_for_protocol(src_ip, dst_ip, sport, dport, payload, proto)
            if parsed_protocol:
                # 使用解析后的数据进行匹配
                match_payload_data = parsed_protocol.raw_text or payload
            else:
                match_payload_data = payload

            # 否则继续使用原先的逐包匹配
            from app.services.engine import match_payload
            from app.services.alerter import get_alerter
            from app.metrics import PACKETS_PROCESSED, MATCHES_FOUND

            matches = match_payload(match_payload_data, proto, str(dport), src_ip, str(sport), dst_ip)
            # 若匹配到规则，构造告警并广播（每个匹配一条告警）
            PACKETS_PROCESSED.inc()
            if matches:
                try:
                    MATCHES_FOUND.inc(len(matches))
                except Exception:
                    pass
                alerter = get_alerter(broadcast_callable, loop)
                seen = set()
                for m in matches:
                    rid = m.get("rule_id")
                    if rid in seen:
                        continue
                    seen.add(rid)
                    # per-packet match
                    preview = ""
                    try:
                        preview = payload.decode("latin-1")[:200]
                    except Exception:
                        preview = ""
                    alert_data = {
                        "timestamp": datetime.datetime.now().strftime("%H:%M:%S"),
                        "protocol": proto,
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "packet_summary": f"{proto} {src_ip}:{sport} -> {dst_ip}",
                        "match_rule": rid,
                        "match_text": m.get("match"),
                        "match_type": m.get("type"),
                        "payload_preview": preview,
                        "parsed_protocol": parsed_protocol.protocol if parsed_protocol else None,
                        "protocol_data": parsed_protocol.parsed_data if parsed_protocol else None,
                    }
                    try:
                        alerter.handle_alert(alert_data)
                    except Exception:
                        print("[!] Alerter failed to handle alert", flush=True)

    return _packet_callback


def start_sniffing(interface: Optional[str] = None, loop: Optional[asyncio.AbstractEventLoop] = None, broadcast_callable: Optional[Callable[[dict], Coroutine[Any, Any, Any]]] = None):
    """
    启动抓包；必须传入运行中的主事件循环 `loop`，或者传入自定义的 `broadcast_callable`。
    `broadcast_callable` 应为一个函数，接收 dict 并返回 coroutine（例如：`manager.broadcast`）。
    """
    if loop is None:
        print("[!] Error: Sniffer started without event loop reference!", flush=True)
        return

    if broadcast_callable is None:
        broadcast_callable = _get_default_broadcast_callable()

    print(f"[*] Sniffer active on {interface or 'default'}. Filter: IP", flush=True)
    sniff(iface=interface, prn=_packet_callback_factory(loop, broadcast_callable), filter="ip", store=0)