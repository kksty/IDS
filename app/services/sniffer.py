# -*- coding: utf-8 -*-
import datetime
import asyncio
import logging
import threading
import time
import queue
from typing import Optional, Callable, Coroutine, Any

from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.utils import PcapReader

from app.services.detection import ContextManager
from app.services.http_parser import extract_http_requests, extract_http_responses
from app.services.reassembly_adapter import FlowReassemblerManager
from app.services.behavior_analyzer import get_behavior_analyzer, BehaviorAlert
from app.services.protocol_parser import parse_packet_for_protocol

logger = logging.getLogger("ids.sniffer")


class SnifferManager:
    """网络嗅探管理器，封装所有嗅探相关组件"""

    def __init__(self, context_timeout: Optional[float] = None, max_buffer: Optional[int] = None):
        # 使用配置中的默认值
        if context_timeout is None:
            from app.config import config
            context_timeout = config.CONTEXT_TIMEOUT
        if max_buffer is None:
            from app.config import config
            max_buffer = config.MAX_BUFFER_SIZE

        self.context_manager = ContextManager(timeout=context_timeout)
        self.reassembly_manager = FlowReassemblerManager(max_buffer=max_buffer)
        # 使用全局行为分析器实例，确保与规则告警的关联抑制共享同一状态。
        self.behavior_analyzer = get_behavior_analyzer()

        # TCP flow state for flow keyword matching
        self._tcp_flow_states = {}
        self._tcp_flow_lock = threading.RLock()

        # 将行为分析告警接入统一告警链路（DB 持久化 + WebSocket 广播）
        # 实际写库/广播由 Alerter 的后台线程完成，不阻塞嗅探线程。
        self.behavior_analyzer.add_alert_callback(self._handle_behavior_alert)

        # 由外部在启动时注入的事件循环，用于 WebSocket 广播等异步操作
        self.loop: Optional[asyncio.AbstractEventLoop] = None
        
        # 停止控制
        self._stop_event = threading.Event()
        self._sniffing_active = False

        # 解耦：嗅探回调只入队，worker 后台处理，避免高流量下阻塞 scapy 回调导致丢包。
        from app.config import config
        self._queue: "queue.Queue" = queue.Queue(maxsize=max(1, int(getattr(config, "SNIFFER_QUEUE_SIZE", 5000))))
        self._workers: list[threading.Thread] = []
        self._worker_stop = threading.Event()
        self._worker_count = max(1, int(getattr(config, "SNIFFER_WORKERS", 2)))

    def set_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        """设置事件循环引用，供内部告警广播使用。"""
        self.loop = loop

    def stop(self) -> None:
        """停止嗅探管理器"""
        self._stop_event.set()
        self._sniffing_active = False
        self._worker_stop.set()
        logger.info("SnifferManager stopped")

    def start_workers(self) -> None:
        """启动后台处理 worker（幂等）。"""
        if self._workers:
            return

        self._worker_stop.clear()

        for i in range(self._worker_count):
            t = threading.Thread(target=self._worker_loop, name=f"PacketWorker-{i}", daemon=True)
            self._workers.append(t)
            t.start()

    def join_workers(self, timeout: float = 1.0) -> None:
        """等待 worker 退出（尽量而为）。"""
        for t in list(self._workers):
            try:
                t.join(timeout=timeout)
            except Exception:
                pass
        self._workers = []

    def enqueue_packet(self, packet, broadcast_callable: Callable[[dict], Coroutine[Any, Any, Any]]) -> None:
        """嗅探回调入口：尽快返回，避免阻塞抓包线程。"""
        if self._stop_event.is_set() or self._worker_stop.is_set():
            return
        try:
            self._broadcast_callable = broadcast_callable
        except Exception:
            pass

        from app.metrics import SNIFFER_QUEUE_DEPTH, SNIFFER_ENQUEUED, SNIFFER_DROPPED

        try:
            self._queue.put_nowait(packet)
            SNIFFER_ENQUEUED.inc()
        except queue.Full:
            SNIFFER_DROPPED.inc()
            return
        except Exception:
            SNIFFER_DROPPED.inc()
            return
        finally:
            try:
                SNIFFER_QUEUE_DEPTH.set(self._queue.qsize())
            except Exception:
                pass

    def _worker_loop(self) -> None:
        from app.metrics import SNIFFER_QUEUE_DEPTH, PACKET_PROCESSING_SECONDS

        while not self._worker_stop.is_set() and not self._stop_event.is_set():
            try:
                packet = self._queue.get(timeout=0.2)
            except queue.Empty:
                continue
            except Exception:
                continue

            try:
                try:
                    SNIFFER_QUEUE_DEPTH.set(self._queue.qsize())
                except Exception:
                    pass

                bc = getattr(self, "_broadcast_callable", None)
                if bc is None:
                    # 在线模式应该总有 bc；这里兜底
                    bc = _get_default_broadcast_callable()

                start = time.time()
                try:
                    self.process_packet(packet, bc)
                finally:
                    try:
                        PACKET_PROCESSING_SECONDS.observe(max(0.0, time.time() - start))
                    except Exception:
                        pass
            finally:
                try:
                    self._queue.task_done()
                except Exception:
                    pass

    def is_active(self) -> bool:
        """检查是否正在活动"""
        return self._sniffing_active and not self._stop_event.is_set()

    def process_packet(self, packet, broadcast_callable: Callable[[dict], Coroutine[Any, Any, Any]]) -> None:
        """对外暴露的数据包处理入口（供 scapy 回调使用）。"""
        # 检查是否应该停止
        if self._stop_event.is_set():
            return
            
        # 保存 broadcast_callable，供行为告警 callback 使用
        try:
            self._broadcast_callable = broadcast_callable
        except Exception:
            pass

        try:
            self._process_packet_impl(packet, broadcast_callable)
        except Exception:
            # 确保单个数据包异常不会中断嗅探线程
            logger.exception("Failed to process packet")

    def _is_likely_http_payload(self, payload: bytes) -> bool:
        """快速检测payload是否可能是HTTP流量"""
        if not payload or len(payload) < 10:
            return False

        # 检查前50个字节
        payload_str = payload[:50].decode('utf-8', errors='ignore').strip()

        # HTTP请求方法
        if payload_str.upper().startswith(('GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'OPTIONS ', 'PATCH ', 'CONNECT ', 'TRACE ')):
            return True

        # HTTP响应
        if payload_str.upper().startswith('HTTP/'):
            return True

        # 检查是否包含HTTP头部特征
        if any(header in payload_str.lower() for header in ['host:', 'user-agent:', 'content-type:', 'accept:', 'cookie:']):
            return True

        return False

    def _is_tls_record(self, payload: bytes) -> bool:
        """粗略判断是否为 TLS 记录（用于跳过 HTTPS 密文匹配）。"""
        if not payload or len(payload) < 5:
            return False
        content_type = payload[0]
        # TLS record types: 0x14 change_cipher_spec, 0x15 alert, 0x16 handshake, 0x17 application_data
        if content_type not in (0x14, 0x15, 0x16, 0x17):
            return False
        # TLS version 0x0300-0x0304
        if payload[1] != 0x03:
            return False
        if payload[2] > 0x04:
            return False
        return True

    def _guess_app_proto(self, l4_proto: str, sport: Any, dport: Any, payload: bytes) -> Optional[str]:
        """尽量轻量地猜测应用层协议，用于 Snort sticky buffer 语义过滤等。"""
        try:
            sp = int(sport)
        except Exception:
            sp = None
        try:
            dp = int(dport)
        except Exception:
            dp = None

        proto = (l4_proto or "").upper()

        # TCP: TLS / HTTP
        if proto == "TCP":
            if self._is_tls_record(payload or b""):
                return "tls"
            if self._is_likely_http_payload(payload or b""):
                return "http"

        # 基于常见端口的轻量识别（TCP/UDP）
        ports = {p for p in (sp, dp) if isinstance(p, int)}
        if 53 in ports:
            return "dns"
        if 22 in ports:
            return "ssh"
        if 21 in ports or 20 in ports:
            return "ftp"
        if 25 in ports or 587 in ports or 465 in ports:
            return "smtp"
        if 110 in ports or 995 in ports:
            return "pop3"
        if 143 in ports or 993 in ports:
            return "imap"
        if 23 in ports:
            return "telnet"
        return None

    def _flow_key(self, src_ip: str, src_port: Any, dst_ip: str, dst_port: Any) -> str:
        """生成与方向无关的 flow key（TCP only）。"""
        left = f"{src_ip}:{src_port}"
        right = f"{dst_ip}:{dst_port}"
        if left <= right:
            return f"{left}<->{right}"
        return f"{right}<->{left}"

    def _parse_tcp_flags(self, flags: Any) -> set:
        """将 Scapy flags 转为集合，如 {"S","A"}。"""
        if flags is None:
            return set()
        try:
            s = str(flags)
        except Exception:
            return set()
        return {ch.upper() for ch in s if ch.isalpha()}

    def _update_tcp_flow_state(self, packet, src_ip: str, dst_ip: str, sport: Any, dport: Any, packet_info: dict) -> None:
        """基于 TCP 三次握手推断 client/server 与 established 状态。"""
        try:
            flags = self._parse_tcp_flags(getattr(packet[TCP], "flags", None))
        except Exception:
            flags = set()

        key = self._flow_key(src_ip, sport, dst_ip, dport)
        now = time.time()

        with self._tcp_flow_lock:
            # 清理过期 flow
            if len(self._tcp_flow_states) > 5000:
                expired = [
                    k
                    for k, v in self._tcp_flow_states.items()
                    if now - v.get("last_seen", now) > 180
                ]
                for k in expired:
                    self._tcp_flow_states.pop(k, None)

            st = self._tcp_flow_states.get(key)
            if st is None:
                st = {
                    "client": None,
                    "server": None,
                    "established": False,
                    "last_seen": now,
                }
                self._tcp_flow_states[key] = st
            else:
                st["last_seen"] = now

            # SYN (no ACK) -> client->server
            if "S" in flags and "A" not in flags:
                st["client"] = (src_ip, str(sport))
                st["server"] = (dst_ip, str(dport))
                st["established"] = False

            # SYN+ACK -> server->client, mark established
            if "S" in flags and "A" in flags:
                if st.get("client") is None:
                    st["client"] = (dst_ip, str(dport))
                if st.get("server") is None:
                    st["server"] = (src_ip, str(sport))
                st["established"] = True

            # Any ACK after we have roles indicates established
            if "A" in flags and st.get("client") and st.get("server"):
                st["established"] = True

            # compute flow direction
            flow_dir = None
            if st.get("client") and st.get("server"):
                c_ip, c_port = st["client"]
                s_ip, s_port = st["server"]
                if (src_ip, str(sport)) == (c_ip, c_port) and (dst_ip, str(dport)) == (s_ip, s_port):
                    flow_dir = "to_server"
                elif (src_ip, str(sport)) == (s_ip, s_port) and (dst_ip, str(dport)) == (c_ip, c_port):
                    flow_dir = "to_client"

            packet_info["flow_established"] = bool(st.get("established"))
            packet_info["flow_dir"] = flow_dir

    def _track_auth_event(self, src_ip: str, dst_ip: str, success: bool, auth_type: str) -> None:
        """向行为分析模块提交认证事件（成功/失败）。"""
        try:
            self.behavior_analyzer.process_event({
                "type": "auth",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "success": success,
                "auth_type": auth_type,
            })
        except Exception:
            logger.exception("Failed to track auth event")

    def _handle_behavior_alert(self, alert: BehaviorAlert) -> None:
        """把行为分析模块产生的告警转成系统统一告警格式并交给 Alerter。"""
        try:
            from app.services.alerter import get_alerter

            sev = (getattr(alert, "severity", "") or "").lower()
            priority = 3
            if sev == "high":
                priority = 1
            elif sev == "medium":
                priority = 2

            rule_id = f"behavior:{getattr(alert, 'alert_type', 'unknown')}"
            packet_summary = f"Behavior {getattr(alert, 'alert_type', 'unknown')} from {getattr(alert, 'src_ip', '')}"

            payload_preview = getattr(alert, "description", "") or ""
            try:
                details = getattr(alert, "details", None)
                if isinstance(details, dict) and details:
                    import json
                    details_str = json.dumps(details, ensure_ascii=False, default=str)
                    if details_str:
                        payload_preview = f"{payload_preview} | {details_str}"
            except Exception:
                pass

            details = getattr(alert, "details", {}) if isinstance(getattr(alert, "details", {}), dict) else {}

            alert_data = {
                "timestamp": datetime.datetime.fromtimestamp(getattr(alert, "timestamp", time.time())).strftime("%H:%M:%S"),
                "protocol": "BEHAVIOR",
                "src_ip": getattr(alert, "src_ip", "") or "",
                "dst_ip": str(details.get("target_ip") or "") if isinstance(details, dict) else "",
                "packet_summary": packet_summary,
                "match_rule": rule_id,
                "match_text": getattr(alert, "description", "") or "",
                "match_type": "behavior",
                "payload_preview": payload_preview,
                "pos_start": None,
                "pos_end": None,
                # 附加字段（websocket 直接展示可用；DB 当前不存）
                "severity": sev,
                "priority": priority,
            }

            # 复用当前 sniffer 的 broadcast_callable（由 start_sniffing/process_pcap 传入），
            # 这样行为告警也能正常走 WebSocket 广播。
            alerter = get_alerter(getattr(self, "_broadcast_callable", None), self.loop)
            alerter.handle_alert(alert_data)
        except Exception:
            logger.exception("Failed to handle behavior alert")

    def _priority_to_severity(self, priority: Any) -> str:
        """将规则优先级映射为严重度：1=high, 2=medium, 3=low。"""
        try:
            pr = int(priority)
            if pr <= 1:
                return "high"
            if pr == 2:
                return "medium"
            return "low"
        except Exception:
            return "low"

    def _process_packet_impl(self, packet, broadcast_callable: Callable[[dict], Coroutine[Any, Any, Any]]):
        """实际的数据包处理实现"""
        from scapy.packet import Raw

        # Extract IP layer
        if not packet.haslayer(IP):
            return  # Skip non-IP packets
        
        ip_layer = packet[IP]
        ip_proto = getattr(ip_layer, "proto", None)
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

        # 解析层策略：
        # - scapy 负责抓包与原始 payload 提取（稳定，且不会误触发应用层解析）
        # - pcapkit（若启用）仅用于 L3/L4 字段标准化，不做应用层解析
        #   为避免 pcapkit 在解析半包/非 HTTP 数据时深入到 HTTPv1 造成噪声，这里只使用 scapy 的解析结果。
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        
        sport = getattr(packet, "sport", "")
        dport = getattr(packet, "dport", "")

        packet_info = {
            "ip_id": getattr(ip_layer, "id", None),
            "ip_proto": ip_proto,
            "flags": None,
            "seq": None,
            "ack": None,
            "window": None,
            "icmp_type": None,
            "icmp_code": None,
            "app_proto": None,
        }

        # 如果 pypcapkit 未能识别协议或未启用，回退到 scapy 基于协议层的判定
        if not proto:
            try:
                if packet.haslayer(TCP):
                    proto = "TCP"
                    sport = getattr(packet[TCP], "sport", sport)
                    dport = getattr(packet[TCP], "dport", dport)
                elif packet.haslayer(UDP):
                    proto = "UDP"
                    sport = getattr(packet[UDP], "sport", sport)
                    dport = getattr(packet[UDP], "dport", dport)
                elif packet.haslayer(ICMP):
                    proto = "ICMP"
                    sport = str(packet[ICMP].type)
                    dport = str(packet[ICMP].code)
                    packet_info.update(
                        {
                            "icmp_type": getattr(packet[ICMP], "type", None),
                            "icmp_code": getattr(packet[ICMP], "code", None),
                        }
                    )
                else:
                    proto = ""
            except Exception:
                proto = ""

        # 将真实 payload 送入行为分析（EWMA 流量突增、会话速率、端口扫描等）。
        # 注意：行为分析依赖 src/dst/ports/payload_size，因此在解析出 proto 与端口后执行。
        try:
            if proto in ("TCP", "UDP"):
                try:
                    src_port_i = int(sport)
                except Exception:
                    src_port_i = 0
                try:
                    dst_port_i = int(dport)
                except Exception:
                    dst_port_i = 0
            else:
                src_port_i = 0
                dst_port_i = 0

            self.behavior_analyzer.analyze_packet(
                {
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": src_port_i,
                    "dst_port": dst_port_i,
                    "protocol": proto or "unknown",
                    "payload": payload or b"",
                }
            )
        except Exception:
            logger.exception("Behavior analysis failed")

        # 若无法识别 L4 协议则保持为空（仅做基础匹配）

        skip_raw_match = False

        # 标记应用层协议（轻量）；用于引擎侧做 sticky buffer / service 过滤，减少误报。
        try:
            packet_info["app_proto"] = self._guess_app_proto(proto or "", sport, dport, payload or b"")
        except Exception:
            packet_info["app_proto"] = None

        # 协议语义化缓冲区：为 Snort sticky buffer 类规则提供可匹配的“字段载体”。
        # 例如 dns_query/ftp_command 等，不再只是过滤，而是可精确匹配字段文本。
        sticky_buffers: dict[str, bytes] = {}
        try:
            app_proto = (packet_info.get("app_proto") or "").lower()
            if app_proto in ("dns", "smtp", "pop3") and proto in ("TCP", "UDP"):
                try:
                    src_port_i = int(sport)
                except Exception:
                    src_port_i = 0
                try:
                    dst_port_i = int(dport)
                except Exception:
                    dst_port_i = 0

                parsed = parse_packet_for_protocol(src_ip, dst_ip, src_port_i, dst_port_i, payload or b"", proto)
                if parsed and isinstance(getattr(parsed, "parsed_data", None), dict):
                    pd = parsed.parsed_data
                    if (parsed.protocol or "").lower() == "dns":
                        domain = pd.get("domain")
                        rtype = pd.get("record_type")
                        parts = []
                        if domain:
                            parts.append(str(domain))
                        if rtype:
                            parts.append(str(rtype))
                        if parts:
                            sticky_buffers["dns_query"] = ("\n".join(parts)).encode("utf-8", errors="ignore")
                    elif (parsed.protocol or "").lower() == "smtp":
                        cmds = pd.get("commands") or []
                        if isinstance(cmds, list) and cmds:
                            sticky_buffers["smtp_command"] = ("\n".join([str(x) for x in cmds if x is not None])).encode(
                                "utf-8", errors="ignore"
                            )
                    elif (parsed.protocol or "").lower() == "pop3":
                        cmds = pd.get("commands") or []
                        if isinstance(cmds, list) and cmds:
                            sticky_buffers["pop_command"] = ("\n".join([str(x) for x in cmds if x is not None])).encode(
                                "utf-8", errors="ignore"
                            )
        except Exception:
            sticky_buffers = {}

        if sticky_buffers:
            packet_info["sticky_buffers"] = sticky_buffers

        if proto == "TCP":
            # extract seq if available
            seq: Optional[int] = None
            try:
                seq = int(packet[TCP].seq)
            except Exception:
                seq = None

            packet_info.update(
                {
                    "flags": getattr(packet[TCP], "flags", None),
                    "seq": getattr(packet[TCP], "seq", None),
                    "ack": getattr(packet[TCP], "ack", None),
                    "window": getattr(packet[TCP], "window", None),
                }
            )

            # 更新 TCP flow 状态（client/server/established）
            try:
                self._update_tcp_flow_state(packet, src_ip, dst_ip, sport, dport, packet_info)
            except Exception:
                pass

            # --- Protocol semantic events (HTTP/FTP auth) ---
            # Use per-direction reassembled stream and simple parsers to derive auth success/failure.
            # HTTP:
            #   - client->server: remember login attempt if request path looks like login/auth
            #   - server->client: parse response status code; if 2xx => success, 401/403 => fail
            # FTP:
            #   - client->server: track PASS command
            #   - server->client: parse response code 230(success)/530(fail)
            # 语义事件提取依赖 TCP 重组结果 ready（下方单次重组得到）。
            # --- end semantic events ---

            # Skip TLS records (HTTPS) to avoid false positives from encrypted data
            if self._is_tls_record(payload):
                return

            # Quick HTTP detection before expensive stream reassembly
            is_likely_http = self._is_likely_http_payload(payload)
            if is_likely_http:
                skip_raw_match = True

            # 为 HTTP 流维护轻量级上下文（主要用于去重元数据等）
            ctx = None
            if is_likely_http:
                ctx = self.context_manager.append_to_flow("TCP", src_ip, dst_ip, b"", sport=sport, dport=dport)

            # 使用基于 seq 的重组逻辑；若缺少 seq，则回退到简单 buffer 方式
            ready = b""
            if seq is not None:
                # 使用 FlowReassemblerManager 做严格的按序重组
                try:
                    ready = self.reassembly_manager.append(
                        "TCP", src_ip, dst_ip, seq, payload, sport=sport, dport=dport
                    )
                except Exception:
                    logger.exception("Flow reassembly failed; falling back to direct payload for this segment")
                    ready = b""
            elif ctx is not None:
                # best-effort: append raw payload to context buffer and attempt HTTP extraction
                ctx.append(payload)
                ready = ctx.get_buffer()

            if not is_likely_http and ready and self._is_likely_http_payload(ready):
                is_likely_http = True
                skip_raw_match = True

            # --- Semantic auth extraction (consume ready once) ---
            try:
                if ready:
                    # --- FTP control channel (port 21) ---
                    try:
                        # client->server
                        if int(dport) == 21:
                            ftp_ctx = self.context_manager.append_to_flow("FTP", src_ip, dst_ip, b"", sport=sport, dport=dport)
                            buf = ftp_ctx.meta.setdefault("ftp_c2s_buf", bytearray())
                            buf.extend(ready)
                            if len(buf) > 8192:
                                del buf[: len(buf) - 8192]
                            while True:
                                idx = buf.find(b"\r\n")
                                if idx < 0:
                                    break
                                line = bytes(buf[:idx])
                                del buf[: idx + 2]
                                up = line.strip().upper()
                                if up.startswith(b"PASS "):
                                    ftp_ctx.meta["ftp_last_pass_ts"] = time.time()
                        # server->client
                        if int(sport) == 21:
                            ftp_ctx = self.context_manager.append_to_flow("FTP", dst_ip, src_ip, b"", sport=dport, dport=sport)
                            buf = ftp_ctx.meta.setdefault("ftp_s2c_buf", bytearray())
                            buf.extend(ready)
                            if len(buf) > 8192:
                                del buf[: len(buf) - 8192]
                            while True:
                                idx = buf.find(b"\r\n")
                                if idx < 0:
                                    break
                                line = bytes(buf[:idx])
                                del buf[: idx + 2]
                                if len(line) >= 3 and line[:3].isdigit():
                                    code = line[:3].decode("ascii", errors="ignore")
                                    if code == "230":
                                        self._track_auth_event(dst_ip, src_ip, True, "ftp")
                                    elif code == "530":
                                        self._track_auth_event(dst_ip, src_ip, False, "ftp")
                    except Exception:
                        logger.debug("FTP auth semantic parsing failed", exc_info=True)

                    # --- HTTP login (best-effort) ---
                    try:
                        # client->server HTTP request: mark login attempt
                        if int(dport) in (80, 8080, 8000, 443):
                            if self._is_likely_http_payload(ready):
                                http_ctx = self.context_manager.append_to_flow("HTTPAUTH", src_ip, dst_ip, b"", sport=sport, dport=dport)
                                reqs, _ = extract_http_requests(ready)
                                for r in reqs:
                                    path = (r.get("path") or "").lower()
                                    method = (r.get("method") or "").upper()
                                    if method in ("POST", "PUT") and any(x in path for x in ("login", "signin", "auth", "session")):
                                        http_ctx.meta["http_login_attempt_ts"] = time.time()
                        # server->client HTTP response: parse status line
                        if int(sport) in (80, 8080, 8000, 443):
                            s = ready[:128]
                            if s.startswith(b"HTTP/"):
                                line_end = s.find(b"\r\n")
                                if line_end > 0:
                                    line = s[:line_end].decode("latin-1", errors="ignore")
                                    parts = line.split()
                                    if len(parts) >= 2 and parts[1].isdigit():
                                        code = int(parts[1])
                                        http_ctx = self.context_manager.append_to_flow("HTTPAUTH", dst_ip, src_ip, b"", sport=dport, dport=sport)
                                        last_attempt = http_ctx.meta.get("http_login_attempt_ts")
                                        if last_attempt and (time.time() - float(last_attempt) <= 10.0):
                                            if 200 <= code < 400:
                                                self._track_auth_event(dst_ip, src_ip, True, "http")
                                            elif code in (401, 403):
                                                self._track_auth_event(dst_ip, src_ip, False, "http")
                    except Exception:
                        logger.debug("HTTP auth semantic parsing failed", exc_info=True)
            except Exception:
                logger.debug("Semantic auth extraction failed", exc_info=True)

            if ready and is_likely_http and ctx is not None:
                # 尝试提取 HTTP 请求/响应
                requests, consumed_req = extract_http_requests(ready)
                responses, consumed_res = extract_http_responses(ready)
                consumed = max(consumed_req, consumed_res)
                if consumed and seq is None:
                    # 如果来自本地 ctx.buffer（fallback），移除已消费字节
                    try:
                        del ctx.buffer[:consumed]
                    except Exception:
                        ctx.clear()

                # 对每个完整请求做匹配（仅在 HTTP 字段内匹配）
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
                    # 把 path 与 body 一并作为匹配载体（包含 URL 解码后的内容）
                    try:
                        from urllib.parse import unquote_plus

                        headers = req.get("headers") or {}
                        header_bytes = b"\r\n".join(
                            [
                                f"{k}: {v}".encode("utf-8", errors="ignore")
                                for k, v in headers.items()
                            ]
                        )

                        path_raw = req.get("path") or ""
                        path_decoded = unquote_plus(path_raw)

                        body_raw = req.get("body") or b""
                        body_text = body_raw.decode("utf-8", errors="ignore")
                        body_decoded = body_text
                        content_type = (headers.get("content-type") or "").lower()
                        if "application/x-www-form-urlencoded" in content_type:
                            body_decoded = unquote_plus(body_text)

                        base = f"{req.get('method') or ''} {path_raw} {req.get('version') or ''}".encode(
                            "utf-8", errors="ignore"
                        )
                        decoded_blob = f"{path_decoded}\n{body_decoded}".encode(
                            "utf-8", errors="ignore"
                        )

                        match_payload_src = (
                            base
                            + b"\r\n"
                            + header_bytes
                            + b"\r\n\r\n"
                            + body_raw
                            + b"\n\n"
                            + decoded_blob
                        )
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

                    packet_info_stream = dict(packet_info)
                    packet_info_stream["stream"] = True
                    matches = match_payload(
                        match_payload_src,
                        "TCP",
                        str(dport),
                        src_ip,
                        str(sport),
                        dst_ip,
                        packet_info_stream,
                    )
                    if matches:
                        logger.info(f"ALERT: Found {len(matches)} matches for HTTP request: {method} {req.get('path')}")
                        try:
                            MATCHES_FOUND.inc(len(matches))
                        except Exception:
                            pass
                        alerter = get_alerter(broadcast_callable, self.loop)
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
                            priority = m.get("priority")
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
                                # 添加上下文信息
                                "match_context": m.get("context", {}),
                                "priority": priority,
                                "severity": self._priority_to_severity(priority),
                            }
                            try:
                                alerter.handle_alert(alert_data)
                                # 记录规则告警到行为分析器的关联抑制系统
                                from app.services.behavior_analyzer import get_behavior_analyzer
                                b_analyzer = get_behavior_analyzer()
                                b_analyzer.record_rule_alert(rid, src_ip, dst_ip)
                                
                                # 记录规则告警到关联引擎
                                from app.services.correlation_engine import get_correlation_engine
                                corr_engine = get_correlation_engine()
                                corr_engine.add_alert(src_ip, rid, is_behavior=False)
                            except Exception:
                                logger.exception("[!] Alerter failed to handle alert")

                # 对每个完整响应做匹配（仅匹配响应行，避免 TLS/乱码误报）
                for resp in responses:
                    try:
                        status_code = resp.get("status_code")
                        status_text = resp.get("status_text") or ""
                        version = resp.get("version") or "HTTP/"
                        status_line = f"{version} {status_code or ''} {status_text}".strip().encode(
                            "utf-8", errors="ignore"
                        )
                        match_payload_src = status_line
                    except Exception:
                        match_payload_src = resp.get("raw", b"")

                    from app.services.engine import match_payload
                    from app.services.alerter import get_alerter
                    from app.metrics import MATCHES_FOUND, PACKETS_PROCESSED

                    PACKETS_PROCESSED.inc()

                    packet_info_stream = dict(packet_info)
                    packet_info_stream["stream"] = True
                    matches = match_payload(
                        match_payload_src,
                        "TCP",
                        str(dport),
                        src_ip,
                        str(sport),
                        dst_ip,
                        packet_info_stream,
                    )
                    if matches:
                        try:
                            MATCHES_FOUND.inc(len(matches))
                        except Exception:
                            pass
                        alerter = get_alerter(broadcast_callable, self.loop)
                        seen = set()
                        for m in matches:
                            rid = m.get("rule_id")
                            if rid in seen:
                                continue
                            seen.add(rid)
                            packet_summary = f"HTTP {src_ip}:{sport} -> {dst_ip} {status_code or ''}".strip()
                            priority = m.get("priority")
                            alert_data = {
                                "timestamp": datetime.datetime.now().strftime("%H:%M:%S"),
                                "protocol": proto,
                                "src_ip": src_ip,
                                "dst_ip": dst_ip,
                                "packet_summary": packet_summary,
                                "match_rule": rid,
                                "match_text": m.get("match"),
                                "match_type": m.get("type"),
                                "payload_preview": status_line.decode("utf-8", errors="ignore") or packet_summary,
                                "match_context": m.get("context", {}),
                                "priority": priority,
                                "severity": self._priority_to_severity(priority),
                            }
                            try:
                                alerter.handle_alert(alert_data)
                                from app.services.behavior_analyzer import get_behavior_analyzer
                                b_analyzer = get_behavior_analyzer()
                                b_analyzer.record_rule_alert(rid, src_ip, dst_ip)

                                from app.services.correlation_engine import get_correlation_engine
                                corr_engine = get_correlation_engine()
                                corr_engine.add_alert(src_ip, rid, is_behavior=False)
                            except Exception:
                                logger.exception("[!] Alerter failed to handle alert")

            # done processing HTTP requests for this packet
            # Continue to process non-HTTP TCP/UDP payloads for pattern matching
            pass

        # Process all TCP/UDP payloads for pattern matching (including non-HTTP traffic)
        if proto in ("TCP", "UDP") and payload and not (proto == "TCP" and skip_raw_match):
            # UDP 不做重组/HTTP 抽取：保持 datagram 语义，仅对 payload 做规则匹配。

            # 统一去重窗口：同一 (rule_id + flow) 在窗口内只报一次。
            # 用于实现“单包命中后 stream 不再报”（以及 stream 命中后单包不再报）。
            try:
                dedupe_ctx = self.context_manager.append_to_flow(
                    proto, src_ip, dst_ip, b"", sport=sport, dport=dport
                )
                dedupe_meta = dedupe_ctx.meta
            except Exception:
                dedupe_meta = {}

            now_ts = time.time()
            unified = dedupe_meta.setdefault("recent_unified_rule_hits", {}) if isinstance(dedupe_meta, dict) else {}
            try:
                for k, t in list(unified.items()):
                    if now_ts - t > 2.0:
                        del unified[k]
            except Exception:
                pass

            # 额外增强：对非 HTTP 的 TCP 尝试做 stream 级匹配（更接近 Snort stream）。
            # - 仅当能拿到 seq 时启用（依赖重组器输出连续数据）
            # - 控制匹配窗口，避免对大流量造成 CPU 压力
            if proto == "TCP":
                try:
                    seq_val = None
                    try:
                        seq_val = int(packet[TCP].seq) if packet.haslayer(TCP) else None
                    except Exception:
                        seq_val = None

                    is_http_like = self._is_likely_http_payload(payload)
                    if seq_val is not None and (not is_http_like):
                        stream_ready = self.reassembly_manager.append(
                            "TCP", src_ip, dst_ip, seq_val, payload, sport=sport, dport=dport
                        )
                        if stream_ready:
                            from app.services.engine import match_payload
                            from app.services.alerter import get_alerter
                            from app.metrics import MATCHES_FOUND, PACKETS_PROCESSED

                            PACKETS_PROCESSED.inc()

                            stream_chunk = stream_ready[:8192]
                            packet_info_stream = dict(packet_info)
                            packet_info_stream["stream"] = True
                            stream_matches = match_payload(
                                stream_chunk,
                                "TCP",
                                str(dport),
                                src_ip,
                                str(sport),
                                dst_ip,
                                packet_info_stream,
                            )
                            if stream_matches:
                                try:
                                    MATCHES_FOUND.inc(len(stream_matches))
                                except Exception:
                                    pass

                                alerter = get_alerter(broadcast_callable, self.loop)

                                seen = set()
                                for m in stream_matches:
                                    rid = m.get("rule_id")
                                    if rid in seen:
                                        continue
                                    seen.add(rid)

                                    fp = f"{rid}|{src_ip}|{dst_ip}|{sport}|{dport}"
                                    if fp in unified:
                                        continue
                                    unified[fp] = now_ts

                                    packet_summary = f"TCP(stream) {src_ip}:{sport} -> {dst_ip}:{dport}"
                                    preview = stream_chunk[:100].decode("utf-8", errors="ignore").strip() or packet_summary

                                    priority = m.get("priority")
                                    alert_data = {
                                        "timestamp": datetime.datetime.now().strftime("%H:%M:%S"),
                                        "protocol": proto,
                                        "src_ip": src_ip,
                                        "dst_ip": dst_ip,
                                        "packet_summary": packet_summary,
                                        "match_rule": rid,
                                        "match_text": m.get("match"),
                                        "match_type": (m.get("type") or "") + ":stream",
                                        "payload_preview": preview,
                                        # 添加上下文信息
                                        "match_context": m.get("context", {}),
                                        "priority": priority,
                                        "severity": self._priority_to_severity(priority),
                                    }
                                    try:
                                        alerter.handle_alert(alert_data)
                                        # 记录规则告警到行为分析器的关联抑制系统
                                        from app.services.behavior_analyzer import get_behavior_analyzer
                                        b_analyzer = get_behavior_analyzer()
                                        b_analyzer.record_rule_alert(rid, src_ip, dst_ip)
                                        
                                        # 记录规则告警到关联引擎
                                        from app.services.correlation_engine import get_correlation_engine
                                        corr_engine = get_correlation_engine()
                                        corr_engine.add_alert(src_ip, rid, is_behavior=False)
                                    except Exception:
                                        logger.exception("[!] Alerter failed to handle stream alert")
                except Exception:
                    logger.exception("Stream-level TCP matching failed")

            # For all TCP/UDP payloads (including those that weren't HTTP), do pattern matching
            from app.services.engine import match_payload
            from app.services.alerter import get_alerter
            from app.metrics import MATCHES_FOUND, PACKETS_PROCESSED

            PACKETS_PROCESSED.inc()

            # For non-HTTP traffic, match the raw payload
            packet_info_single = dict(packet_info)
            packet_info_single["stream"] = False
            matches = match_payload(
                payload,
                proto,
                str(dport),
                src_ip,
                str(sport),
                dst_ip,
                packet_info_single,
            )
            if matches:
                logger.info(f"ALERT: Found {len(matches)} matches for {proto} payload: {src_ip}:{sport} -> {dst_ip}:{dport}")
                try:
                    MATCHES_FOUND.inc(len(matches))
                except Exception:
                    pass
                alerter = get_alerter(broadcast_callable, self.loop)

                # Create packet summary for non-HTTP traffic
                packet_summary = f"{proto} {src_ip}:{sport} -> {dst_ip}:{dport}"

                # Deduplication for non-HTTP alerts
                seen = set()
                for m in matches:
                    rid = m.get("rule_id")
                    if rid in seen:
                        continue
                    seen.add(rid)

                    # unified cross-mode dedupe
                    fp = f"{rid}|{src_ip}|{dst_ip}|{sport}|{dport}"
                    if fp in unified:
                        continue
                    unified[fp] = now_ts

                    priority = m.get("priority")
                    alert_data = {
                        "timestamp": datetime.datetime.now().strftime("%H:%M:%S"),
                        "protocol": proto,
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "packet_summary": packet_summary,
                        "match_rule": rid,
                        "match_text": m.get("match"),
                        "match_type": m.get("type"),
                        "payload_preview": payload[:100].decode('utf-8', errors='ignore').strip() or packet_summary,
                        # 添加上下文信息
                        "match_context": m.get("context", {}),
                        "priority": priority,
                        "severity": self._priority_to_severity(priority),
                    }
                    try:
                        alerter.handle_alert(alert_data)
                        # 记录规则告警到行为分析器的关联抑制系统
                        from app.services.behavior_analyzer import get_behavior_analyzer
                        b_analyzer = get_behavior_analyzer()
                        b_analyzer.record_rule_alert(rid, src_ip, dst_ip)
                        # 记录规则告警到关联引擎
                        from app.services.correlation_engine import get_correlation_engine
                        corr_engine = get_correlation_engine()
                        corr_engine.add_alert(src_ip, rid, is_behavior=False)
                    except Exception:
                        logger.exception("[!] Alerter failed to handle alert")

        elif payload:
            # Non-TCP/UDP (e.g., ICMP or other IP protocols)
            from app.services.engine import match_payload
            from app.services.alerter import get_alerter
            from app.metrics import MATCHES_FOUND, PACKETS_PROCESSED

            PACKETS_PROCESSED.inc()

            packet_info_single = dict(packet_info)
            packet_info_single["stream"] = False
            proto_for_match = proto or "IP"
            matches = match_payload(
                payload,
                proto_for_match,
                str(dport) if dport != "" else None,
                src_ip,
                str(sport) if sport != "" else None,
                dst_ip,
                packet_info_single,
            )
            if matches:
                logger.info(
                    f"ALERT: Found {len(matches)} matches for {proto_for_match} payload: {src_ip}:{sport} -> {dst_ip}:{dport}"
                )
                try:
                    MATCHES_FOUND.inc(len(matches))
                except Exception:
                    pass
                alerter = get_alerter(broadcast_callable, self.loop)

                packet_summary = f"{proto_for_match} {src_ip}:{sport} -> {dst_ip}:{dport}"

                seen = set()
                for m in matches:
                    rid = m.get("rule_id")
                    if rid in seen:
                        continue
                    seen.add(rid)

                    priority = m.get("priority")
                    alert_data = {
                        "timestamp": datetime.datetime.now().strftime("%H:%M:%S"),
                        "protocol": proto_for_match,
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "packet_summary": packet_summary,
                        "match_rule": rid,
                        "match_text": m.get("match"),
                        "match_type": m.get("type"),
                        "payload_preview": payload[:100].decode('utf-8', errors='ignore').strip() or packet_summary,
                        "match_context": m.get("context", {}),
                        "priority": priority,
                        "severity": self._priority_to_severity(priority),
                    }
                    try:
                        alerter.handle_alert(alert_data)
                        from app.services.behavior_analyzer import get_behavior_analyzer
                        b_analyzer = get_behavior_analyzer()
                        b_analyzer.record_rule_alert(rid, src_ip, dst_ip)

                        from app.services.correlation_engine import get_correlation_engine
                        corr_engine = get_correlation_engine()
                        corr_engine.add_alert(src_ip, rid, is_behavior=False)
                    except Exception:
                        logger.exception("[!] Alerter failed to handle alert")

# 全局单例实例（保持向后兼容）
from app.config import config
_sniffer_manager = SnifferManager(
    context_timeout=config.CONTEXT_TIMEOUT,
    max_buffer=config.MAX_BUFFER_SIZE,
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
_pypcapkit_stats_lock = threading.Lock()


def _get_default_broadcast_callable() -> Callable[[dict], Coroutine[Any, Any, Any]]:
    """获取默认的广播回调函数"""
    from app.routers.websocket import manager
    return manager.broadcast


def _packet_callback_factory(loop: asyncio.AbstractEventLoop,
                             broadcast_callable: Callable[[dict], Coroutine[Any, Any, Any]],
                             manager: SnifferManager):
    """创建数据包回调函数"""
    def _packet_callback(packet):
        manager.enqueue_packet(packet, broadcast_callable)

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
    # 注入事件循环引用，供内部告警广播使用
    try:
        if loop is not None:
            manager.set_loop(loop)
    except Exception:
        logger.exception("Failed to set event loop on SnifferManager")

    # 设置活动标志
    manager._sniffing_active = True

    # 启动后台 worker
    try:
        manager.start_workers()
    except Exception:
        logger.exception("Failed to start packet workers")

    logger.info(f"Sniffer active on {interface or 'default'}. Filter: IP")
    try:
        from app.config import config
        bpf = config.BPF_FILTER or "ip"
        logger.info(f"Using BPF filter: {bpf}")
        sniff(
            iface=interface,
            prn=_packet_callback_factory(loop, broadcast_callable, manager),
            filter=bpf,
            store=0,
            promisc=True,
            stop_filter=lambda _p: bool(manager._stop_event.is_set()),
        )
    finally:
        manager._sniffing_active = False
        try:
            manager._worker_stop.set()
            manager.join_workers(timeout=1.0)
        except Exception:
            logger.exception("Failed to stop packet workers")


def process_pcap(
    pcap_path: str,
    loop: Optional[asyncio.AbstractEventLoop] = None,
    manager: Optional[SnifferManager] = None,
    broadcast_callable: Optional[Callable[[dict], Coroutine[Any, Any, Any]]] = None,
    max_packets: Optional[int] = None,
    progress_callback: Optional[Callable[[int, float, float], None]] = None,
    stop_event: Optional[threading.Event] = None,
) -> int:
    """离线 PCAP 分析入口。

    复用在线抓包的整个处理链路：对于 PCAP 中的每个 scapy Packet，
    直接调用 SnifferManager.process_packet 进行协议解析、规则匹配和告警。

    Args:
        pcap_path: PCAP 文件路径
        loop: 可选事件循环（若提供，仍可进行 WebSocket 广播；否则仅写入 DB）
        manager: 嗅探管理器实例（默认使用全局单例）
        broadcast_callable: 广播协程（默认使用 WebSocket manager.broadcast；离线模式可留空）
        max_packets: 可选的最大处理包数（用于快速实验）

    Returns:
        实际处理的数据包数量
    """
    if manager is None:
        manager = _sniffer_manager

    # 离线分析时，如果提供循环则注入；否则只做持久化，不做 WebSocket 广播
    if loop is not None:
        try:
            manager.set_loop(loop)
        except Exception:
            logger.exception("Failed to set event loop on SnifferManager for PCAP processing")

    if broadcast_callable is None:
        # 离线模式下可以不广播，这里提供一个空广播协程以保持接口一致性
        async def _noop_broadcast(_: dict) -> None:  # type: ignore[override]
            return None

        broadcast_callable = _noop_broadcast

    count = 0
    start_ts = time.time()
    last_log_ts = start_ts
    last_log_count = 0
    log_interval_sec = 5.0
    log_interval_pkts = 1000
    try:
        with PcapReader(pcap_path) as reader:
            for pkt in reader:
                if stop_event is not None and stop_event.is_set():
                    break
                manager.process_packet(pkt, broadcast_callable)
                count += 1
                if count % log_interval_pkts == 0:
                    now = time.time()
                    delta_t = max(now - last_log_ts, 1e-6)
                    delta_n = count - last_log_count
                    rate = delta_n / delta_t
                    logger.info(
                        "PCAP progress: %d packets processed (%.1f pkt/s)",
                        count,
                        rate,
                    )
                    if progress_callback:
                        try:
                            progress_callback(count, rate, now - start_ts)
                        except Exception:
                            logger.debug("PCAP progress callback failed", exc_info=True)
                    last_log_ts = now
                    last_log_count = count
                if max_packets is not None and count >= max_packets:
                    break
    except FileNotFoundError:
        logger.error("PCAP file not found: %s", pcap_path)
    except Exception:
        logger.exception("Error while processing PCAP file: %s", pcap_path)

    total_time = max(time.time() - start_ts, 1e-6)
    if progress_callback:
        try:
            progress_callback(count, count / total_time, total_time)
        except Exception:
            logger.debug("PCAP progress callback failed", exc_info=True)
    logger.info(
        "Processed %d packets from PCAP %s in %.2fs (avg %.1f pkt/s)",
        count,
        pcap_path,
        total_time,
        count / total_time,
    )
    return count