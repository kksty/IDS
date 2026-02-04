# -*- coding: utf-8 -*-
"""告警关联引擎 - 基于时间窗口的跨规则/行为告警关联分析"""

import time
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Any
from collections import defaultdict, deque
import logging
from datetime import datetime, timedelta

logger = logging.getLogger("ids.correlation")

class CorrelationEngine:
    """告警关联引擎
    
    功能：
    - 跟踪每个src_ip在时间窗口内的规则命中情况
    - 分析规则多样性（不同规则的命中数）
    - 结合行为告警（如端口扫描、暴力破解）生成更高级别的"可疑攻击者"告警
    """
    
    def __init__(self, window_size: int = None, min_rule_diversity: int = None, 
                 min_alerts: int = None, behavior_alert_weight: int = None):
        """
        Args:
            window_size: 关联分析时间窗口（秒）
            min_rule_diversity: 触发关联的最小不同规则数
            min_alerts: 触发关联的最小告警数
            behavior_alert_weight: 行为告警的权重（相当于多少个规则告警）
        """
        from app.config import config
        self.window_size = window_size or config.CORR_WINDOW_SIZE
        self.min_rule_diversity = min_rule_diversity or config.CORR_MIN_RULE_DIVERSITY
        self.min_alerts = min_alerts or config.CORR_MIN_ALERTS
        self.behavior_alert_weight = behavior_alert_weight or config.CORR_BEHAVIOR_WEIGHT
        
        # 存储每个src_ip的告警历史：src_ip -> deque[(timestamp, rule_id, is_behavior)]
        self.alert_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        
        # 可疑攻击者列表：src_ip -> (timestamp, severity)
        self.suspected_attackers: Dict[str, Tuple[float, str]] = {}
    
    def add_alert(self, src_ip: str, rule_id: str, is_behavior: bool = False):
        """记录告警到关联引擎"""
        now = time.time()
        self.alert_history[src_ip].append((now, rule_id, is_behavior))
        
        # 清理过期记录
        self._cleanup_expired()
        
        # 检查是否达到可疑攻击者条件
        self._check_suspected_attacker(src_ip)
    
    def _cleanup_expired(self):
        """清理过期的告警记录"""
        now = time.time()
        cutoff = now - self.window_size
        
        for src_ip in list(self.alert_history.keys()):
            # 移除过期记录
            while self.alert_history[src_ip] and self.alert_history[src_ip][0][0] < cutoff:
                self.alert_history[src_ip].popleft()
            
            # 如果该IP没有活跃告警，移除其记录
            if not self.alert_history[src_ip]:
                del self.alert_history[src_ip]
    
    def _check_suspected_attacker(self, src_ip: str):
        """检查指定IP是否达到可疑攻击者条件"""
        now = time.time()
        alerts = self.alert_history.get(src_ip, [])
        
        if not alerts:
            return
        
        # 计算有效告警数（行为告警有额外权重）
        rule_counts = defaultdict(int)
        total_weighted_alerts = 0
        
        for ts, rule_id, is_behavior in alerts:
            if is_behavior:
                total_weighted_alerts += self.behavior_alert_weight
            else:
                total_weighted_alerts += 1
                rule_counts[rule_id] += 1
        
        # 检查条件
        rule_diversity = len(rule_counts)
        is_suspected = (rule_diversity >= self.min_rule_diversity and 
                       total_weighted_alerts >= self.min_alerts)
        
        if is_suspected:
            # 确定严重性级别
            severity = "high" if total_weighted_alerts >= self.min_alerts * 2 else "medium"
            
            # 更新可疑攻击者列表
            self.suspected_attackers[src_ip] = (now, severity)
            logger.info(f"Marked {src_ip} as suspected attacker (severity: {severity})")
            # 持久化到数据库（upsert）——容错处理，避免影响主线程
            try:
                from app.db import SessionLocal
                from app.models.db_models import SuspectedAttackerModel
                session = SessionLocal()
                try:
                    # 如果存在则更新，否则插入
                    existing = session.query(SuspectedAttackerModel).filter(SuspectedAttackerModel.src_ip == src_ip).first()
                    fs = datetime.fromtimestamp(now)
                    if existing:
                        existing.severity = severity
                        existing.first_seen = fs if existing.first_seen is None else existing.first_seen
                        existing.description = f"Detected suspected attacker {src_ip} (severity={severity})"
                    else:
                        sa = SuspectedAttackerModel(
                            src_ip=src_ip,
                            severity=severity,
                            first_seen=fs,
                            description=f"Detected suspected attacker {src_ip} (severity={severity})",
                        )
                        session.add(sa)
                    session.commit()
                except Exception:
                    session.rollback()
                finally:
                    try:
                        session.close()
                    except Exception:
                        pass
            except Exception:
                logger.exception("Failed to persist suspected attacker")
    
    def get_suspected_attackers(self) -> Dict[str, Tuple[float, str]]:
        """获取当前可疑攻击者列表"""
        # 先清理过期记录
        self._cleanup_expired()
        
        # 清理过期的可疑攻击者标记（超过窗口时间2倍）
        now = time.time()
        cutoff = now - self.window_size * 2
        self.suspected_attackers = {
            ip: (ts, sev) 
            for ip, (ts, sev) in self.suspected_attackers.items() 
            if ts >= cutoff
        }
        
        return self.suspected_attackers
    
    def is_suspected_attacker(self, src_ip: str) -> Tuple[bool, Optional[str]]:
        """检查IP是否为可疑攻击者，并返回其严重性"""
        entry = self.suspected_attackers.get(src_ip)
        if entry:
            return True, entry[1]
        return False, None


# 全局单例实例
_correlation_engine = CorrelationEngine()

def get_correlation_engine() -> CorrelationEngine:
    """获取全局关联引擎实例"""
    return _correlation_engine


def generate_correlation_alert(src_ip: str, severity: str, details: Dict[str, Any]) -> Dict[str, Any]:
    """生成关联告警数据结构"""
    return {
        "timestamp": datetime.now().strftime("%H:%M:%S"),
        "protocol": "CORRELATION",
        "src_ip": src_ip,
        "dst_ip": "",  # 关联告警不针对特定目标
        "packet_summary": f"Suspected attacker: {src_ip}",
        "match_rule": f"correlation:suspected_attacker",
        "match_text": f"Suspected attacker activity from {src_ip}",
        "match_type": "correlation",
        "payload_preview": f"Multiple attack patterns detected from {src_ip}",
        "severity": severity,
        "priority": 1 if severity == "high" else 2,
        "details": details
    }