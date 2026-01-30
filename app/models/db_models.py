from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, Boolean, JSON, DateTime
from sqlalchemy.sql import func

from app.db import Base


class RuleModel(Base):
    __tablename__ = "rules"

    id = Column(Integer, primary_key=True, index=True)
    rule_id = Column(String(128), unique=True, index=True, nullable=False)
    name = Column(String(256), nullable=True)
    action = Column(String(32), default="alert")
    priority = Column(Integer, default=3)

    protocol = Column(String(32), nullable=True)
    src = Column(String(64), default="any")
    src_ports = Column(JSON, nullable=True)
    direction = Column(String(8), default="->")
    dst = Column(String(64), default="any")
    dst_ports = Column(JSON, nullable=True)

    # pattern stored as JSON if list, or plain string
    pattern = Column(Text, nullable=False)
    pattern_type = Column(String(32), default="string")

    description = Column(Text, nullable=True)
    category = Column(String(128), nullable=True)
    tags = Column(JSON, nullable=True)
    rule_metadata = Column(JSON, nullable=True)
    enabled = Column(Boolean, default=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now())


class AlertModel(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    rule_id = Column(String(128), nullable=False)
    match_text = Column(Text, nullable=True)
    src_ip = Column(String(64), nullable=True)
    dst_ip = Column(String(64), nullable=True)
    pos_start = Column(Integer, nullable=True)
    pos_end = Column(Integer, nullable=True)
    payload_preview = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
