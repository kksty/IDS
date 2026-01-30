from fastapi import APIRouter, Query
from typing import List, Optional
from datetime import datetime, timedelta, timezone
from sqlalchemy import func, case, text

from app.db import SessionLocal
from app.models.db_models import AlertModel, RuleModel

router = APIRouter(prefix="/api/alerts", tags=["Alerts"])


@router.get("/", response_model=List[dict])
async def recent_alerts(limit: int = 50):
    session = SessionLocal()
    try:
        rows = session.query(AlertModel).order_by(AlertModel.created_at.desc()).limit(limit).all()
        out = []
        for r in rows:
            out.append({
                "id": r.id,
                "rule_id": r.rule_id,
                "match_text": r.match_text,
                "src_ip": r.src_ip,
                "dst_ip": r.dst_ip,
                "pos_start": r.pos_start,
                "pos_end": r.pos_end,
                "payload_preview": r.payload_preview,
                "created_at": r.created_at.isoformat() if r.created_at is not None else None,
            })
        return out
    finally:
        session.close()


@router.get("/count")
async def alerts_count():
    """返回数据库中告警的总数（用于持久化的总告警计数）。"""
    session = SessionLocal()
    try:
        total = session.query(AlertModel).count()
        return {"total": total}
    finally:
        session.close()


@router.get("/stats")
async def alerts_stats(
    range: Optional[str] = Query("24h", description="时间范围: 1h,24h,7d,30d,all"),
    interval: Optional[str] = Query(None, description="聚合间隔: '30m','1h','1d' (优先于自动选择)"),
    top_n: int = Query(20, description="Top N for IPs/rules"),
):
    """返回聚合的告警统计：按时间桶的 high/medium/low 计数，以及 Top 规则和 Top 源 IP 列表。

    - `range` 支持：`1h`, `24h`, `7d`, `30d`, `all`。
    - 聚合在数据库中完成以节省带宽与前端计算。
    """
    # compute time window
    now = datetime.now(timezone.utc)
    offsets = {
        "1h": timedelta(hours=1),
        "24h": timedelta(hours=24),
        "7d": timedelta(days=7),
        "30d": timedelta(days=30),
    }
    start = None
    if range and range != "all":
        delta = offsets.get(range, offsets["24h"])
        start = now - delta

    # determine aggregation interval: honor explicit `interval` param if provided
    # supported: '30m', '1h', '1d'
    if interval is None:
        if range in ("1h", "24h"):
            interval = "1h"
        else:
            interval = "1d"

    session = SessionLocal()
    try:
        # For 30-minute buckets we build a SQL expression that groups into half-hour slots.
        if interval == "30m":
            # Use raw SQL to compute bucket: date_trunc('hour', created_at) + floor(date_part('minute', created_at)/30) * interval '30 minutes'
            sql = text(
                "SELECT bucket, SUM(CASE WHEN r.priority <= 1 THEN 1 ELSE 0 END) AS high, "
                "SUM(CASE WHEN r.priority = 2 THEN 1 ELSE 0 END) AS medium, "
                "SUM(CASE WHEN r.priority >= 3 THEN 1 ELSE 0 END) AS low, COUNT(*) AS total FROM ("
                "  SELECT *, (date_trunc('hour', created_at) + floor(date_part('minute', created_at)/30)::int * interval '30 minutes') AS bucket "
                "  FROM alerts "
                "  WHERE (:start IS NULL OR created_at >= :start)"
                ") a LEFT JOIN rules r ON r.rule_id = a.rule_id GROUP BY bucket ORDER BY bucket"
            )
            params = {"start": start}
            rows = session.execute(sql, params).fetchall()
            buckets = []
            for row in rows:
                # row.bucket may be datetime
                bucket_val = row[0]
                buckets.append({
                    "bucket": bucket_val.isoformat() if bucket_val is not None else None,
                    "high": int(row[1] or 0),
                    "medium": int(row[2] or 0),
                    "low": int(row[3] or 0),
                    "total": int(row[4] or 0),
                })
        else:
            # hourly or daily via date_trunc
            bucket_unit = "hour" if interval == "1h" else "day"
            q = session.query(
                func.date_trunc(bucket_unit, AlertModel.created_at).label("bucket"),
                func.coalesce(func.sum(case([(RuleModel.priority <= 1, 1)], else_=0)), 0).label("high"),
                func.coalesce(func.sum(case([(RuleModel.priority == 2, 1)], else_=0)), 0).label("medium"),
                func.coalesce(func.sum(case([(RuleModel.priority >= 3, 1)], else_=0)), 0).label("low"),
                func.count().label("total"),
            ).outerjoin(RuleModel, RuleModel.rule_id == AlertModel.rule_id)

            if start:
                q = q.filter(AlertModel.created_at >= start)

            q = q.group_by("bucket").order_by("bucket")

            buckets = []
            for row in q.all():
                buckets.append({
                    "bucket": row.bucket.isoformat() if row.bucket is not None else None,
                    "high": int(row.high),
                    "medium": int(row.medium),
                    "low": int(row.low),
                    "total": int(row.total),
                })

        # top rules
        qr = session.query(AlertModel.rule_id, func.count().label("count"))
        if start:
            qr = qr.filter(AlertModel.created_at >= start)
        qr = qr.group_by(AlertModel.rule_id).order_by(func.count().desc()).limit(top_n)
        top_rules = [{"rule_id": r.rule_id, "count": int(r.count)} for r in qr.all()]

        # top source IPs
        qi = session.query(AlertModel.src_ip.label("ip"), func.count().label("count"))
        if start:
            qi = qi.filter(AlertModel.created_at >= start)
        qi = qi.group_by(AlertModel.src_ip).order_by(func.count().desc()).limit(top_n)
        top_ips = [{"ip": r.ip or "unknown", "count": int(r.count)} for r in qi.all()]

        total_count = session.query(func.count(AlertModel.id))
        if start:
            total_count = total_count.filter(AlertModel.created_at >= start)
        total_count = int(total_count.scalar() or 0)

        return {"buckets": buckets, "top_rules": top_rules, "top_ips": top_ips, "total": total_count}
    finally:
        session.close()


@router.delete("/")
async def clear_all_alerts():
    """清空所有告警记录"""
    session = SessionLocal()
    try:
        # 获取删除前的数量
        count_before = session.query(AlertModel).count()
        
        # 删除所有告警
        session.query(AlertModel).delete()
        session.commit()
        
        return {
            "status": "cleared", 
            "deleted_count": count_before,
            "message": f"成功清空了 {count_before} 条告警记录"
        }
    except Exception as e:
        session.rollback()
        return {"status": "error", "message": f"清空告警失败: {str(e)}"}
    finally:
        session.close()


@router.delete("/{alert_id}")
async def delete_alert(alert_id: int):
        """删除指定 ID 的告警记录。"""
        session = SessionLocal()
        try:
            row = session.query(AlertModel).filter(AlertModel.id == alert_id).first()
            if not row:
                return {"status": "not_found", "id": alert_id}
            session.delete(row)
            session.commit()
            return {"status": "deleted", "id": alert_id}
        finally:
            session.close()


@router.delete("/")
async def clear_all_alerts():
    """清空所有告警记录"""
    session = SessionLocal()
    try:
        # 获取删除前的数量
        count_before = session.query(AlertModel).count()

        # 删除所有记录
        session.query(AlertModel).delete()
        session.commit()

        return {
            "status": "cleared",
            "deleted_count": count_before,
            "message": f"成功清空了 {count_before} 条告警记录"
        }
    finally:
        session.close()


@router.get("/parser-stats")
async def parser_stats():
    """获取数据包解析器的统计信息"""
    try:
        from app.services.sniffer import _pypcapkit_stats
        total = _pypcapkit_stats["success"] + _pypcapkit_stats["failure"]
        success_rate = (_pypcapkit_stats["success"] / total * 100) if total > 0 else 0

        return {
            "pypcapkit_available": True,
            "pypcapkit_stats": {
                "success": _pypcapkit_stats["success"],
                "failure": _pypcapkit_stats["failure"],
                "total": total,
                "success_rate": round(success_rate, 2)
            }
        }
    except ImportError:
        return {
            "pypcapkit_available": False,
            "pypcapkit_stats": None
        }
