# -*- coding: utf-8 -*-
"""关联分析监控器 - 定期检查可疑攻击者并生成关联告警"""

import time
import threading
import logging
from datetime import datetime
from typing import Dict, Tuple, Optional

from app.services.correlation_engine import get_correlation_engine
from app.services.alerter import get_alerter

logger = logging.getLogger("ids.correlation_monitor")

class CorrelationMonitor:
    """关联分析监控器
    
    定期检查关联引擎中的可疑攻击者，并生成高级别告警
    """
    
    def __init__(self, interval: int = 60):
        """
        Args:
            interval: 检查间隔（秒）
        """
        self.interval = interval
        self._engine = get_correlation_engine()
        self._alerter = get_alerter()
        self._stop_event = threading.Event()
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        # per-src cooldown to avoid repeated alerts
        from app.config import config
        self._cooldown = config.CORR_ALERT_COOLDOWN
        self._last_alert_ts = {}
        
    def start(self):
        """启动监控线程"""
        self._thread.start()
        logger.info(f"Correlation monitor started with {self.interval}s interval")
        
    def stop(self):
        """停止监控线程"""
        self._stop_event.set()
        self._thread.join(timeout=2.0)
        
    def _monitor_loop(self):
        """监控循环"""
        while not self._stop_event.is_set():
            try:
                self._check_suspected_attackers()
            except Exception:
                logger.exception("Error in correlation monitor loop")
            
            # 等待直到下次检查时间
            time.sleep(self.interval)
    
    def _check_suspected_attackers(self):
        """检查可疑攻击者并生成告警"""
        attackers = self._engine.get_suspected_attackers()
        
        for src_ip, (timestamp, severity) in attackers.items():
            now = time.time()
            last_ts = self._last_alert_ts.get(src_ip, 0.0)
            if now - last_ts < self._cooldown:
                continue
            self._last_alert_ts[src_ip] = now
            # 获取该IP的详细活动信息
            details = {
                "first_seen": datetime.fromtimestamp(timestamp).isoformat(),
                "severity": severity,
                "description": f"Suspected attacker detected ({severity} severity)"
            }
            
            # 生成关联告警
            alert = {
                "timestamp": datetime.now().strftime("%H:%M:%S"),
                "protocol": "CORRELATION",
                "src_ip": src_ip,
                "dst_ip": "",  # 不针对特定目标
                "packet_summary": f"Suspected attacker: {src_ip}",
                "match_rule": f"correlation:suspected_attacker_{severity}",
                "match_text": f"Multiple attack patterns detected from {src_ip}",
                "match_type": "correlation",
                "payload_preview": f"Suspected attacker activity from {src_ip}",
                "severity": severity,
                "priority": 1 if severity == "high" else 2,
                "details": details
            }
            
            # 发送告警
            try:
                self._alerter.handle_alert(alert)
                logger.info(f"Generated correlation alert for {src_ip} (severity: {severity})")
            except Exception:
                logger.exception(f"Failed to generate correlation alert for {src_ip}")


# 全局单例实例
_correlation_monitor = CorrelationMonitor()

def start_correlation_monitor():
    """启动全局关联监控器"""
    _correlation_monitor.start()

def stop_correlation_monitor():
    """停止全局关联监控器"""
    _correlation_monitor.stop()