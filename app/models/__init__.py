# -*- coding: utf-8 -*-
from datetime import datetime
from typing import Optional

from .rule import Rule
from pydantic import BaseModel


# 将核心模型在包顶层导出，便于 `from app.models import Rule, Alert` 这样的导入
class Alert(BaseModel):
    alert_id: str
    timestamp: datetime
    severity: str
    rule_id: str
    src_ip: str
    dst_ip: str
    packet_summary: str
    raw_hex: Optional[str] = None


__all__ = ["Rule", "Alert"]
