# -*- coding: utf-8 -*-
"""行为分析模块 - 检测异常流量模式和攻击行为。

支持的分析类型：
1. 连接频率分析 - 检测端口扫描、DDoS等
2. 认证失败分析 - 检测爆破攻击
3. 流量异常分析 - 检测异常数据包模式
4. 会话分析 - 检测异常会话行为
"""

import time
import threading
from typing import Dict, List, Tuple, Optional, Any
from collections import defaultdict, deque
from dataclasses import dataclass
import logging
from datetime import datetime, timedelta

logger = logging.getLogger("ids.behavior")


@dataclass
class ConnectionEvent:
    """连接事件记录"""
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    action: str  # 'connect', 'auth_success', 'auth_fail', etc.


@dataclass
class BehaviorAlert:
    """行为分析告警"""
    alert_type: str
    severity: str
    src_ip: str
    description: str
    details: Dict[str, Any]
    timestamp: float


class ConnectionTracker:
    """连接频率跟踪器 - 检测扫描和DDoS"""

    def __init__(self, window_size: int = None, max_connections_per_window: int = None, 
                 port_scan_window: int = None, port_scan_threshold: int = None):
        from app.config import config
        
        self.window_size = window_size or config.CONNECTION_WINDOW_SIZE
        self.max_connections = max_connections_per_window or config.MAX_CONNECTIONS_PER_WINDOW

        # 连接时间戳（用于连接频率）
        self.connections: Dict[str, deque] = defaultdict(lambda: deque(maxlen=5000))

        # 端口访问历史（用于端口扫描）：(src_ip:dst_ip:proto) -> deque[(ts, dst_port)]
        self.port_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=5000))
        
        # 目标IP历史（用于DDoS检测）：(src_ip:proto) -> deque[(ts, dst_ip)]
        self.target_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=5000))
        self.port_scan_window = port_scan_window or config.PORT_SCAN_WINDOW
        self.port_scan_threshold = port_scan_threshold or config.PORT_SCAN_THRESHOLD
        self.port_scan_min_targets = config.PORT_SCAN_MIN_TARGETS
        self.port_scan_min_ports = config.PORT_SCAN_MIN_PORTS
        self.alert_cooldown = config.BEHAVIOR_ALERT_COOLDOWN
        self.port_scan_cooldown = config.PORT_SCAN_ALERT_COOLDOWN
        self.high_conn_cooldown = config.HIGH_CONN_ALERT_COOLDOWN

        # per-src cooldown tracking
        self._last_alert_ts: Dict[str, float] = defaultdict(float)
        self._last_port_scan_ts: Dict[str, float] = defaultdict(float)
        self._last_high_conn_ts: Dict[str, float] = defaultdict(float)

    def add_connection(self, src_ip: str, dst_ip: str, dst_port: int, protocol: str) -> Optional[BehaviorAlert]:
        """记录连接事件并检查是否异常"""
        proto = (protocol or "").lower()
        key = f"{src_ip}:{dst_ip}:{proto}"
        now = time.time()

        # 添加到连接历史
        self.connections[key].append(now)

        # 添加端口访问历史
        try:
            self.port_history[key].append((now, int(dst_port)))
            # 添加目标IP历史
            self.target_history[f"{src_ip}:{proto}"].append((now, dst_ip))
        except Exception:
            # dst_port 可能是空字符串等
            pass

        # 清理过期记录
        cutoff = now - self.window_size
        while self.connections[key] and self.connections[key][0] < cutoff:
            self.connections[key].popleft()

        # 检查连接频率
        recent_connections = len(self.connections[key])
        if recent_connections > self.max_connections:
            last_ts = self._last_high_conn_ts.get(src_ip, 0.0)
            if now - last_ts < self.high_conn_cooldown:
                return None
            self._last_high_conn_ts[src_ip] = now
            return BehaviorAlert(
                alert_type="high_connection_rate",
                severity="high",
                src_ip=src_ip,
                description=f"High connection rate: {recent_connections} connections in {self.window_size}s",
                details={
                    "connection_count": recent_connections,
                    "window_size": self.window_size,
                    "target_ip": dst_ip,
                    "target_port": dst_port,
                    "protocol": protocol
                },
                timestamp=now
            )

        # 检查端口扫描模式
        port_scan = self._detect_port_scan(src_ip, proto)
        if port_scan:
            last_ts = self._last_port_scan_ts.get(src_ip, 0.0)
            if now - last_ts < self.port_scan_cooldown:
                return None
            self._last_port_scan_ts[src_ip] = now
            return BehaviorAlert(
                alert_type="port_scan",
                severity="medium",
                src_ip=src_ip,
                description=f"Port scanning detected: {port_scan.get('unique_ports')} ports in {port_scan.get('window_seconds')}s",
                details=port_scan,
                timestamp=now,
            )

        return None

    def _detect_port_scan(self, src_ip: str, protocol: str) -> Optional[Dict[str, Any]]:
        """检测端口扫描行为

        规则：在 port_scan_window 内访问不同端口数超过 port_scan_threshold。
        """
        if (protocol or "").lower() != "tcp":
            return None

        now = time.time()
        cutoff = now - self.port_scan_window
        details = {}

        # 检测端口扫描
        port_scan_detected = False
        port_stats = defaultdict(int)
        target_stats = defaultdict(int)
        
        # 扫描所有目标IP的端口访问情况
        for key in list(self.port_history.keys()):
            if key.startswith(f"{src_ip}:") and key.endswith(f":{protocol.lower()}"):
                dq = self.port_history[key]
                # 清理过期记录
                while dq and dq[0][0] < cutoff:
                    dq.popleft()
                
                # 统计端口访问
                for _, port in dq:
                    port_stats[port] += 1
                
                # 统计目标IP
                target_ip = key.split(":")[1]
                target_stats[target_ip] += len(dq)
        
        # 检测DDoS模式 (多个目标IP)
        target_ips = list(target_stats.keys())
        if len(target_ips) >= self.port_scan_min_targets:
            details.update({
                "unique_targets": len(target_ips),
                "top_targets": sorted(target_ips, key=lambda x: target_stats[x], reverse=True)[:5],
                "target_counts": {ip: target_stats[ip] for ip in target_ips[:5]}
            })
            port_scan_detected = True
        
        # 检测端口扫描模式 (单个目标IP的多个端口)
        ports = list(port_stats.keys())
        if len(ports) >= self.port_scan_min_ports:
            top_ports = sorted(ports, key=lambda x: port_stats[x], reverse=True)[:50]
            details.update({
                "unique_ports": len(ports),
                "ports": top_ports,
                "port_counts": {port: port_stats[port] for port in top_ports[:10]},
                "window_seconds": self.port_scan_window,
            })
            port_scan_detected = True

        return details if port_scan_detected else None


class AuthenticationTracker:
    """认证失败跟踪器 - 检测爆破攻击"""

    def __init__(self, max_failures: int = None, window_size: int = None):
        from app.config import config
        
        self.max_failures = max_failures or config.MAX_AUTH_FAILURES
        self.window_size = window_size or config.AUTH_WINDOW_SIZE
        self.failures: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))

    def add_auth_event(self, src_ip: str, dst_ip: str, success: bool, auth_type: str = "unknown") -> Optional[BehaviorAlert]:
        """记录认证事件"""
        key = f"{src_ip}:{dst_ip}:{auth_type}"
        now = time.time()

        if not success:
            self.failures[key].append(now)

            # 清理过期记录
            cutoff = now - self.window_size
            while self.failures[key] and self.failures[key][0] < cutoff:
                self.failures[key].popleft()

            failure_count = len(self.failures[key])
            if failure_count >= self.max_failures:
                return BehaviorAlert(
                    alert_type="brute_force",
                    severity="high",
                    src_ip=src_ip,
                    description=f"Brute force attack detected: {failure_count} failed authentications",
                    details={
                        "failure_count": failure_count,
                        "window_size": self.window_size,
                        "target_ip": dst_ip,
                        "auth_type": auth_type,
                        "failure_times": list(self.failures[key])
                    },
                    timestamp=now
                )

        return None


class TrafficAnomalyDetector:
    """流量异常检测器（EWMA 基线）。

    目标：对每个 src_ip 维护 packets/sec 与 bytes/sec 的 EWMA 基线，检测突增。

    触发规则：
    - 当前速率 > baseline * factor 并持续 N 个采样窗口

    说明：为了轻量与稳定，这里用固定采样窗口（sample_interval）统计速率。
    """

    def __init__(
        self,
        sample_interval: float = None,
        alpha: float = None,
        spike_factor_packets: float = None,
        spike_factor_bytes: float = None,
        sustain_windows: int = None,
        warmup_windows: int = None,
    ):
        from app.config import config
        
        self.sample_interval = sample_interval or config.SAMPLE_INTERVAL
        self.alpha = alpha or config.EWMA_ALPHA
        self.spike_factor_packets = spike_factor_packets or config.SPIKE_FACTOR_PACKETS
        self.spike_factor_bytes = spike_factor_bytes or config.SPIKE_FACTOR_BYTES
        self.sustain_windows = sustain_windows or config.SUSTAIN_WINDOWS
        self.warmup_windows = warmup_windows or config.WARMUP_WINDOWS

        # per ip state
        self.state: Dict[str, Dict[str, Any]] = {}

    def _get_state(self, src_ip: str) -> Dict[str, Any]:
        st = self.state.get(src_ip)
        if st is None:
            now = time.time()
            st = {
                "last_ts": now,
                "pkt_count": 0,
                "byte_count": 0,
                "ewma_pps": None,
                "ewma_bps": None,
                "windows": 0,
                "spike_windows": 0,
                "last_alert_ts": 0.0,
            }
            self.state[src_ip] = st
        return st

    def analyze_packet(self, src_ip: str, packet_size: int) -> Optional[BehaviorAlert]:
        """分析数据包并检测异常"""
        now = time.time()

        # 简单的异常检测：如果数据包大小异常大
        if packet_size > 65535:  # 超过最大MTU
            return BehaviorAlert(
                alert_type="oversized_packet",
                severity="medium",
                src_ip=src_ip,
                description=f"Oversized packet detected: {packet_size} bytes",
                details={"packet_size": packet_size},
                timestamp=now,
            )

        if not src_ip:
            return None

        st = self._get_state(src_ip)
        st["pkt_count"] += 1
        st["byte_count"] += max(0, int(packet_size))

        elapsed = now - float(st["last_ts"])
        if elapsed < self.sample_interval:
            return None

        # compute current rates
        pps = st["pkt_count"] / elapsed if elapsed > 0 else 0.0
        bps = st["byte_count"] / elapsed if elapsed > 0 else 0.0

        st["pkt_count"] = 0
        st["byte_count"] = 0
        st["last_ts"] = now
        st["windows"] += 1

        # update EWMA baseline
        if st["ewma_pps"] is None:
            st["ewma_pps"] = pps
        else:
            st["ewma_pps"] = self.alpha * pps + (1 - self.alpha) * float(st["ewma_pps"])

        if st["ewma_bps"] is None:
            st["ewma_bps"] = bps
        else:
            st["ewma_bps"] = self.alpha * bps + (1 - self.alpha) * float(st["ewma_bps"])

        # warmup: per-IP initialization stage
        if st["windows"] < self.warmup_windows:
            return None

        base_pps = float(st["ewma_pps"] or 0.0)
        base_bps = float(st["ewma_bps"] or 0.0)

        # avoid divide-by-zero / tiny baseline
        base_pps = max(base_pps, 1e-6)
        base_bps = max(base_bps, 1e-6)

        spike = (pps > base_pps * self.spike_factor_packets) or (bps > base_bps * self.spike_factor_bytes)

        if spike:
            st["spike_windows"] += 1
        else:
            st["spike_windows"] = 0

        # sustain check
        if st["spike_windows"] >= self.sustain_windows:
            # rate-limit alerts per ip
            if now - float(st["last_alert_ts"]) < 30.0:
                return None
            st["last_alert_ts"] = now

            severity = "high" if (pps > base_pps * (self.spike_factor_packets * 2) or bps > base_bps * (self.spike_factor_bytes * 2)) else "medium"

            return BehaviorAlert(
                alert_type="traffic_spike",
                severity=severity,
                src_ip=src_ip,
                description=(
                    f"Traffic spike detected: {pps:.1f} pkt/s (baseline {base_pps:.1f}), "
                    f"{bps/1024:.1f} KB/s (baseline {base_bps/1024:.1f})"
                ),
                details={
                    "pps": pps,
                    "bps": bps,
                    "baseline_pps": base_pps,
                    "baseline_bps": base_bps,
                    "spike_factor_packets": self.spike_factor_packets,
                    "spike_factor_bytes": self.spike_factor_bytes,
                    "sample_interval": self.sample_interval,
                    "sustain_windows": self.sustain_windows,
                    "warmup_windows": self.warmup_windows,
                },
                timestamp=now,
            )

        return None


class SessionTracker:
    """会话行为跟踪器"""

    def __init__(self, session_timeout: int = None):
        from app.config import config
        
        self.active_sessions: Dict[str, Dict[str, Any]] = {}
        self.session_timeout = session_timeout or config.SESSION_TIMEOUT  # 1小时

    def track_session(self, src_ip: str, dst_ip: str, protocol: str, payload_size: int) -> Optional[BehaviorAlert]:
        """跟踪会话行为"""
        session_key = f"{src_ip}:{dst_ip}:{protocol}"
        now = time.time()

        if session_key not in self.active_sessions:
            self.active_sessions[session_key] = {
                'start_time': now,
                'total_bytes': 0,
                'packet_count': 0,
                'last_activity': now
            }

        session = self.active_sessions[session_key]
        session['total_bytes'] += payload_size
        session['packet_count'] += 1
        session['last_activity'] = now

        # 检测异常会话
        duration = now - session['start_time']
        if duration > 0:
            bytes_per_second = session['total_bytes'] / duration
            packets_per_second = session['packet_count'] / duration

            # 只对持续时间足够长的会话进行速率检查，避免短连接误报
            min_duration_for_rate_check = 0.1  # 100ms
            if duration >= min_duration_for_rate_check:
                # 检测DDoS-like行为
                if packets_per_second > 1000 or bytes_per_second > 1024*1024:  # 1MB/s
                    return BehaviorAlert(
                        alert_type="suspicious_session",
                        severity="high",
                        src_ip=src_ip,
                        description=f"Suspicious session activity: {packets_per_second:.1f} pkt/s, {bytes_per_second/1024:.1f} KB/s",
                        details={
                            "target_ip": dst_ip,
                            "protocol": protocol,
                            "duration": duration,
                            "total_bytes": session['total_bytes'],
                            "packet_count": session['packet_count'],
                            "bytes_per_second": bytes_per_second,
                            "packets_per_second": packets_per_second
                        },
                        timestamp=now
                    )

        # 清理过期会话
        expired = []
        for key, session_data in self.active_sessions.items():
            if now - session_data['last_activity'] > self.session_timeout:
                expired.append(key)

        for key in expired:
            del self.active_sessions[key]

        return None


class BehaviorAnalyzer:
    """行为分析主控制器

    支持两类输入：
    1) packet/connection 级别（analyze_packet / track_connection）
    2) 语义事件级别（process_event），用于认证成功/失败、登录尝试等高层信号

    设计目标：让行为分析成为“统计/关联层”，与规则检测互补。
    """

    def __init__(self):
        self.connection_tracker = ConnectionTracker()
        self.auth_tracker = AuthenticationTracker()
        self.traffic_detector = TrafficAnomalyDetector()
        self.session_tracker = SessionTracker()
        self.alert_callbacks: List[callable] = []
        from app.services.correlation_engine import get_correlation_engine
        self.correlation_engine = get_correlation_engine()

        # 关联抑制：相同 topic+key 在窗口内只发一次（避免行为与规则或多策略重复刷屏）
        self.correlation_window = 5 * 60  # 5 minutes
        self._recent_topics: Dict[str, float] = {}
        
        # 规则告警历史，用于行为与规则的关联抑制
        self.rule_alert_history: Dict[str, List[Tuple[float, str]]] = defaultdict(list)  # key: src_ip + dst_ip -> [(timestamp, rule_id)]
        self.rule_topic_mapping = self._build_rule_topic_mapping()

    def add_alert_callback(self, callback: callable):
        """添加告警回调函数"""
        self.alert_callbacks.append(callback)

    def process_event(self, event: Dict[str, Any]) -> List[BehaviorAlert]:
        """处理语义事件输入，并返回行为告警。

        支持的 event 示例：
        - {"type": "auth", "src_ip": "1.2.3.4", "dst_ip": "5.6.7.8", "success": False, "auth_type": "ssh"}
        - {"type": "connection", "src_ip": "...", "dst_ip": "...", "src_port": 123, "dst_port": 22, "protocol": "tcp"}

        Returns:
            List[BehaviorAlert]
        """
        et = (event.get("type") or "").lower()
        alerts: List[BehaviorAlert] = []

        if et in ("auth", "authentication"):
            a = self.analyze_auth_event(
                event.get("src_ip", ""),
                event.get("dst_ip", ""),
                bool(event.get("success")),
                event.get("auth_type", "unknown"),
            )
            if a:
                alerts.append(a)
            return alerts

        if et in ("connection", "connect"):
            res = self.track_connection(
                event.get("src_ip", ""),
                event.get("dst_ip", ""),
                int(event.get("src_port") or 0),
                int(event.get("dst_port") or 0),
                str(event.get("protocol") or "unknown"),
            )
            return list(res or [])

        # unknown event type: ignore
        return []

    def _topic_key(self, alert: BehaviorAlert) -> str:
        """生成关联抑制 key：同类告警在窗口内只发一次。"""
        try:
            # src_ip + alert_type 是一个合理的聚合粒度
            return f"{alert.alert_type}|{alert.src_ip}"
        except Exception:
            return "unknown"

    def _build_rule_topic_mapping(self) -> Dict[str, str]:
        """构建规则ID到threat topic的映射"""
        return {
            # brute_force相关规则
            ".*brute.*": "brute_force",
            ".*auth.*fail.*": "brute_force", 
            ".*login.*fail.*": "brute_force",
            ".*password.*": "brute_force",
            ".*ssh.*auth.*": "brute_force",
            ".*ftp.*auth.*": "brute_force",
            
            # scan相关规则
            ".*scan.*": "scan",
            ".*port.*scan.*": "scan",
            ".*nmap.*": "scan",
            ".*recon.*": "scan",
            ".*probe.*": "scan",
            
            # dos相关规则
            ".*dos.*": "dos",
            ".*ddos.*": "dos", 
            ".*flood.*": "dos",
            ".*syn.*flood.*": "dos",
            ".*icmp.*flood.*": "dos",
            ".*traffic.*anomaly.*": "dos",
        }

    def _get_behavior_topic(self, alert_type: str) -> str:
        """根据行为告警类型获取对应的threat topic"""
        topic_map = {
            "brute_force": "brute_force",
            "port_scan": "scan", 
            "high_connection_rate": "dos",
            "traffic_spike": "dos",
            "suspicious_session": "dos",
        }
        return topic_map.get(alert_type, "unknown")

    def _get_rule_topic(self, rule_id: str) -> Optional[str]:
        """根据规则ID获取对应的threat topic"""
        for pattern, topic in self.rule_topic_mapping.items():
            import re
            if re.search(pattern, rule_id, re.IGNORECASE):
                return topic
        return None

    def record_rule_alert(self, rule_id: str, src_ip: str, dst_ip: str):
        """记录规则告警，用于后续的行为告警关联抑制"""
        now = time.time()
        key = f"{src_ip}:{dst_ip}"
        
        # 清理过期记录
        cutoff = now - 300  # 5分钟窗口
        self.rule_alert_history[key] = [(ts, rid) for ts, rid in self.rule_alert_history[key] if ts > cutoff]
        
        # 添加新记录
        self.rule_alert_history[key].append((now, rule_id))

    def _should_suppress_behavior_alert(self, alert: BehaviorAlert) -> bool:
        """检查是否应该抑制行为告警（如果最近有同topic的规则告警）"""
        # 获取行为告警的topic
        behavior_topic = self._get_behavior_topic(alert.alert_type)
        if behavior_topic == "unknown":
            return False
            
        # 获取相关IP
        src_ip = alert.src_ip
        details = getattr(alert, "details", {})
        dst_ip = details.get("target_ip", "") if isinstance(details, dict) else ""
        
        if not src_ip or not dst_ip:
            return False
            
        # 检查最近5分钟内同src_ip+dst_ip的规则告警
        key = f"{src_ip}:{dst_ip}"
        recent_alerts = self.rule_alert_history.get(key, [])
        
        for ts, rule_id in recent_alerts:
            rule_topic = self._get_rule_topic(rule_id)
            if rule_topic and rule_topic == behavior_topic:
                logger.info(f"Suppressing behavior alert {alert.alert_type} due to recent rule {rule_id} with same topic {behavior_topic}")
                return True
                
        return False

    def _should_emit(self, alert: BehaviorAlert) -> bool:
        """关联抑制：窗口内重复 topic 不再发。"""
        now = time.time()
        # cleanup
        try:
            for k, t in list(self._recent_topics.items()):
                if now - t > self.correlation_window:
                    del self._recent_topics[k]
        except Exception:
            pass

        key = self._topic_key(alert)
        if key in self._recent_topics:
            return False
        self._recent_topics[key] = now
        return True

    def analyze_packet(self, packet_info: Dict[str, Any]) -> List[BehaviorAlert]:
        """分析数据包并返回行为告警"""
        alerts = []

        src_ip = packet_info.get('src_ip', '')
        dst_ip = packet_info.get('dst_ip', '')
        src_port = packet_info.get('src_port', 0)
        dst_port = packet_info.get('dst_port', 0)
        protocol = packet_info.get('protocol', 'unknown')
        payload_size = len(packet_info.get('payload', b''))

        # 连接频率分析
        conn_alert = self.connection_tracker.add_connection(src_ip, dst_ip, dst_port, protocol)
        if conn_alert:
            alerts.append(conn_alert)

        # 流量异常分析
        traffic_alert = self.traffic_detector.analyze_packet(src_ip, payload_size)
        if traffic_alert:
            alerts.append(traffic_alert)

        # 会话分析
        session_alert = self.session_tracker.track_session(src_ip, dst_ip, protocol, payload_size)
        if session_alert:
            alerts.append(session_alert)

        # 触发回调（带关联抑制）
        for alert in alerts:
            # 记录到关联引擎
            try:
                self.correlation_engine.add_alert(alert.src_ip, alert.alert_type, is_behavior=True)
            except Exception as e:
                logger.error(f"Failed to add behavior alert to correlation engine: {e}")

            # 检查是否需要抑制行为告警
            if self._should_suppress_behavior_alert(alert):
                logger.debug(f"Suppressed behavior alert {alert.alert_type} due to rule correlation")
                continue
                
            if not self._should_emit(alert):
                continue
            for callback in self.alert_callbacks:
                try:
                    callback(alert)
                except Exception as e:
                    logger.error(f"Alert callback failed: {e}")

        return alerts

    def track_connection(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, protocol: str):
        """跟踪连接信息（简化接口）"""
        packet_info = {
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'protocol': protocol,
            'payload': b''  # 空payload，因为我们只关心连接信息
        }
        return self.analyze_packet(packet_info)

    def analyze_auth_event(self, src_ip: str, dst_ip: str, success: bool, auth_type: str = "unknown") -> Optional[BehaviorAlert]:
        """分析认证事件"""
        alert = self.auth_tracker.add_auth_event(src_ip, dst_ip, success, auth_type)
        if alert:
            # 记录到关联引擎
                try:
                    self.correlation_engine.add_alert(src_ip, alert.alert_type, is_behavior=True)
                except Exception as e:
                    logger.error(f"Failed to add behavior alert to correlation engine: {e}")

                # 检查是否需要抑制（如果有同topic的规则告警）
                if not self._should_suppress_behavior_alert(alert):
                    if self._should_emit(alert):
                        for callback in self.alert_callbacks:
                            try:
                                callback(alert)
                            except Exception as e:
                                logger.error(f"Auth alert callback failed: {e}")
                else:
                    # 抑制告警，但记录统计信息
                    logger.debug(f"Suppressed behavior alert {alert.alert_type} for {src_ip} due to rule correlation")
        return alert


# 全局行为分析器实例
_behavior_analyzer = BehaviorAnalyzer()


def get_behavior_analyzer() -> BehaviorAnalyzer:
    """获取全局行为分析器实例"""
    return _behavior_analyzer


# 使用示例
if __name__ == "__main__":
    def alert_handler(alert: BehaviorAlert):
        print(f"[{alert.severity.upper()}] {alert.alert_type}: {alert.description}")
        print(f"  Source: {alert.src_ip}")
        print(f"  Details: {alert.details}")
        print()

    analyzer = BehaviorAnalyzer()
    analyzer.add_alert_callback(alert_handler)

    # 模拟一些可疑活动
    print("Testing behavior analysis...")

    # 模拟端口扫描
    for i in range(25):
        packet = {
            'src_ip': '192.168.1.100',
            'dst_ip': '192.168.1.1',
            'dst_port': 80 + i,
            'protocol': 'tcp',
            'payload': b'test'
        }
        analyzer.analyze_packet(packet)

    # 模拟认证失败
    for i in range(6):
        analyzer.analyze_auth_event('192.168.1.100', '192.168.1.1', False, 'ssh')

    print("Behavior analysis test completed.")
