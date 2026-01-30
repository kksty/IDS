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

    def __init__(self, window_size: int = 60, max_connections_per_window: int = 100):
        self.window_size = window_size
        self.max_connections = max_connections_per_window
        self.connections: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))

    def add_connection(self, src_ip: str, dst_ip: str, dst_port: int, protocol: str) -> Optional[BehaviorAlert]:
        """记录连接事件并检查是否异常"""
        key = f"{src_ip}:{protocol}"
        now = time.time()

        # 添加到连接历史
        self.connections[key].append(now)

        # 清理过期记录
        cutoff = now - self.window_size
        while self.connections[key] and self.connections[key][0] < cutoff:
            self.connections[key].popleft()

        # 检查连接频率
        recent_connections = len(self.connections[key])
        if recent_connections > self.max_connections:
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
        port_scan = self._detect_port_scan(src_ip, protocol)
        if port_scan:
            return BehaviorAlert(
                alert_type="port_scan",
                severity="medium",
                src_ip=src_ip,
                description="Port scanning detected",
                details=port_scan,
                timestamp=now
            )

        return None

    def _detect_port_scan(self, src_ip: str, protocol: str) -> Optional[Dict[str, Any]]:
        """检测端口扫描行为"""
        if protocol != 'tcp':
            return None

        # 统计最近访问的不同端口数量
        now = time.time()
        cutoff = now - 300  # 5分钟窗口

        ports = set()
        for key, timestamps in self.connections.items():
            if key.startswith(f"{src_ip}:"):
                # 从key中提取目标端口信息（需要修改数据结构来支持）
                # 这里简化处理，实际需要更好的数据结构
                pass

        # 如果在5分钟内访问了超过20个不同端口，认为是扫描
        if len(ports) > 20:
            return {
                "unique_ports": len(ports),
                "ports": list(ports)[:10]  # 只显示前10个
            }

        return None


class AuthenticationTracker:
    """认证失败跟踪器 - 检测爆破攻击"""

    def __init__(self, max_failures: int = 5, window_size: int = 300):
        self.max_failures = max_failures
        self.window_size = window_size
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
    """流量异常检测器"""

    def __init__(self):
        self.baseline_packets: Dict[str, float] = {}  # IP -> packets per second
        self.baseline_bytes: Dict[str, float] = {}    # IP -> bytes per second
        self.last_update = time.time()
        self.learning_period = 3600  # 1小时学习期

    def analyze_packet(self, src_ip: str, packet_size: int) -> Optional[BehaviorAlert]:
        """分析数据包并检测异常"""
        now = time.time()

        # 更新统计
        if src_ip not in self.baseline_packets:
            self.baseline_packets[src_ip] = 0
            self.baseline_bytes[src_ip] = 0

        # 简单的异常检测：如果数据包大小异常大
        if packet_size > 65535:  # 超过最大MTU
            return BehaviorAlert(
                alert_type="oversized_packet",
                severity="medium",
                src_ip=src_ip,
                description=f"Oversized packet detected: {packet_size} bytes",
                details={"packet_size": packet_size},
                timestamp=now
            )

        # 如果是学习期，不产生告警
        if now - self.last_update < self.learning_period:
            return None

        # 这里可以添加更复杂的统计分析
        # 如：基于历史数据的标准差分析

        return None


class SessionTracker:
    """会话行为跟踪器"""

    def __init__(self):
        self.active_sessions: Dict[str, Dict[str, Any]] = {}
        self.session_timeout = 3600  # 1小时

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
    """行为分析主控制器"""

    def __init__(self):
        self.connection_tracker = ConnectionTracker()
        self.auth_tracker = AuthenticationTracker()
        self.traffic_detector = TrafficAnomalyDetector()
        self.session_tracker = SessionTracker()
        self.alert_callbacks: List[callable] = []

    def add_alert_callback(self, callback: callable):
        """添加告警回调函数"""
        self.alert_callbacks.append(callback)

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

        # 触发回调
        for alert in alerts:
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
            for callback in self.alert_callbacks:
                try:
                    callback(alert)
                except Exception as e:
                    logger.error(f"Auth alert callback failed: {e}")
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
