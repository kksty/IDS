# -*- coding: utf-8 -*-
"""关联分析API路由 - 提供可疑攻击者查询接口"""

from fastapi import APIRouter
from typing import List, Dict, Any

from app.services.correlation_engine import get_correlation_engine
from app.db import SessionLocal
from app.models.db_models import SuspectedAttackerModel

router = APIRouter(prefix="/api/correlation", tags=["Correlation"])


@router.get("/attackers", response_model=List[Dict[str, Any]])
async def get_suspected_attackers():
    """获取当前可疑攻击者列表"""
    engine = get_correlation_engine()
    # 从内存引擎和数据库表合并结果，数据库优先保留更丰富的元数据
    attackers = engine.get_suspected_attackers()
    result_map = {}
    # 先将内存中已有的项加入
    for src_ip, (timestamp, severity) in attackers.items():
        result_map[src_ip] = {
            "src_ip": src_ip,
            "severity": severity,
            "first_seen": timestamp,
            "description": f"检测到来自 {src_ip} 的可疑攻击活动（严重性: {severity}）",
        }

    # 再从数据库加载并覆盖/补充字段
    try:
        session = SessionLocal()
        rows = session.query(SuspectedAttackerModel).all()
        for r in rows:
            result_map[r.src_ip] = {
                "src_ip": r.src_ip,
                "severity": r.severity,
                "first_seen": r.first_seen.isoformat() if r.first_seen is not None else None,
                "description": r.description,
            }
    except Exception:
        # 忽略 DB 错误，仅返回内存数据
        pass
    finally:
        try:
            session.close()
        except Exception:
            pass

    # 返回数组形式
    return list(result_map.values())


@router.get("/stats")
async def get_correlation_stats():
    """获取关联分析统计信息"""
    engine = get_correlation_engine()
    attackers = engine.get_suspected_attackers()
    
    # 统计各严重级别的攻击者数量
    severity_counts = {"high": 0, "medium": 0, "low": 0}
    for _, (_, severity) in attackers.items():
        if severity in severity_counts:
            severity_counts[severity] += 1
    
    return {
        "total_attackers": len(attackers),
        "severity_counts": severity_counts,
        "high_risk_attackers": severity_counts["high"],
        "monitoring_ips": len(engine.alert_history)  # 正在监控的IP数量
    }