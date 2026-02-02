import datetime
import asyncio
from typing import Optional, Callable, Coroutine, Any
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP
import logging

from app.services.detection import ContextManager
from app.services.http_parser import extract_http_requests
from app.services.reassembly_adapter import FlowReassemblerManager
from app.services.behavior_analyzer import BehaviorAnalyzer
from app.services.protocol_parser import parse_packet_for_protocol

logger = logging.getLogger("ids.sniffer")


class SnifferManager:
    """网络嗅探管理器，封装所有嗅探相关组件"""

    def __init__(self, context_timeout: float = None, max_buffer: int = None):
        # 使用配置中的默认值
        if context_timeout is None:
            from app.config import config
            context_timeout = config.CONTEXT_TIMEOUT
        if max_buffer is None:
            from app.config import config
            max_buffer = config.MAX_BUFFER_SIZE
            
        self.context_manager = ContextManager(timeout=context_timeout)
        self.reassembly_manager = FlowReassemblerManager(max_buffer=max_buffer)
        self.behavior_analyzer = BehaviorAnalyzer()

    def process_packet(self, packet, broadcast_callable: Callable[[dict], Coroutine[Any, Any, Any]]):
        """处理单个数据包"""
        # 复用原有的包处理逻辑，但使用实例变量而不是全局变量
        return self._process_packet_impl(packet, broadcast_callable)

    def _process_packet_impl(self, packet, broadcast_callable: Callable[[dict], Coroutine[Any, Any, Any]]):
        """实际的数据包处理实现"""
        from scapy.packet import Raw

        # Extract IP layer
        if not packet.haslayer(IP):
            return  # Skip non-IP packets
        
        ip_layer = packet[IP]
        proto = ""  # Initialize proto variable

        try:
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
                elif _HAVE_ICMP and isinstance(pcap_ip.payload, PcapICMP):
                    proto = "ICMP"
                    icmp_info = pcap_ip.payload.info
                    # For ICMP, use type and code as "ports"
                    sport = str(icmp_info.type)
                    dport = str(icmp_info.code)
                    # ICMP payload
                    if hasattr(pcap_ip.payload.payload, 'data'):
                        payload = pcap_ip.payload.payload.data
                else:
                    # Check if this is ICMP using protocol number (fallback)
                    if ip_layer.proto == 1 and packet.haslayer(ICMP):
                        proto = "ICMP"
                        sport = str(packet[ICMP].type)
                        dport = str(packet[ICMP].code)
                        # Get ICMP payload
                        try:
                            payload = bytes(packet[ICMP].payload)
                        except Exception:
                            payload = b""
                    else:
                        # Other protocols or fallback
                        src_ip = ip_layer.src
                        dst_ip = ip_layer.dst
                        sport = getattr(packet, "sport", "")
                        dport = getattr(packet, "dport", "")

                # Special handling for ICMP if not handled by pypcapkit
                if proto == "ICMP" and packet.haslayer(ICMP):
                    sport = str(packet[ICMP].type)
                    dport = str(packet[ICMP].code)

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
            self.behavior_analyzer.track_connection(src_ip, dst_ip, sport, dport, proto)

            # maintain lightweight context for metadata and recent hashes
            ctx = self.context_manager.append_to_flow("TCP", src_ip, dst_ip, b"", sport=sport, dport=dport)

            # feed reassembly manager; if seq missing, fall back to append-bytes
            ready = b""
            # Force using context buffer for HTTP extraction (better for IDS)
            # if seq is not None:
            #     ready = self.reassembly_manager.append("TCP", src_ip, dst_ip, seq, payload, sport=sport, dport=dport)
            # else:
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
                        logger.info(f"ALERT: Found {len(matches)} matches for HTTP request: {method} {req.get('path')}")
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


# 全局单例实例（保持向后兼容）
from app.config import config
_sniffer_manager = SnifferManager(
    context_timeout=config.CONTEXT_TIMEOUT,
    max_buffer=config.MAX_BUFFER_SIZE
)

# 导入pcapkit相关模块
try:
    from pcapkit.protocols.internet import IPv4
    from pcapkit.protocols.transport import TCP as PcapTCP, UDP as PcapUDP
    try:
        from pcapkit.protocols.internet import ICMP as PcapICMP
        _HAVE_ICMP = True
    except ImportError:
        _HAVE_ICMP = False
    _HAVE_PCAPKIT = True
except ImportError:
    _HAVE_PCAPKIT = False
    _HAVE_ICMP = False

# 统计信息
_pypcapkit_stats = {"success": 0, "failure": 0}


def _get_default_broadcast_callable() -> Callable[[dict], Coroutine[Any, Any, Any]]:
    """获取默认的广播回调函数"""
    from app.routers.websocket import manager
    return manager.broadcast


def _packet_callback_factory(loop: asyncio.AbstractEventLoop,
                           broadcast_callable: Callable[[dict], Coroutine[Any, Any, Any]],
                           manager: SnifferManager):
    """创建数据包回调函数"""
    def _packet_callback(packet):
        manager.process_packet(packet, broadcast_callable)

    return _packet_callback
def start_sniffing(interface: Optional[str] = None,
                  loop: Optional[asyncio.AbstractEventLoop] = None,
                  broadcast_callable: Optional[Callable[[dict], Coroutine[Any, Any, Any]]] = None,
                  manager: Optional[SnifferManager] = None):
    """启动网络嗅探

    Args:
        interface: 网络接口名
        loop: 事件循环
        broadcast_callable: 广播回调函数
        manager: 嗅探管理器实例（默认为全局单例）
    """
    if loop is None:
        logger.error("Sniffer started without event loop reference!")
        return

    if broadcast_callable is None:
        broadcast_callable = _get_default_broadcast_callable()

    if manager is None:
        manager = _sniffer_manager

    logger.info(f"Sniffer active on {interface or 'default'}. Filter: IP")
    sniff(iface=interface, prn=_packet_callback_factory(loop, broadcast_callable, manager), filter="ip", store=0, promisc=True)