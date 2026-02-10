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


class ConfigModel(Base):
    __tablename__ = "config"

    id = Column(Integer, primary_key=True, index=True)
    key = Column(String(128), unique=True, index=True, nullable=False)
    value = Column(Text, nullable=True)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class AlertModel(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    rule_id = Column(String(128), index=True, nullable=False)
    match_text = Column(Text, nullable=True)
    src_ip = Column(String(64), nullable=False)
    dst_ip = Column(String(64), nullable=False)
    pos_start = Column(Integer, nullable=True)
    pos_end = Column(Integer, nullable=True)
    payload_preview = Column(Text, nullable=True)
    priority = Column(Integer, nullable=True)
    severity = Column(String(16), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class SuspectedAttackerModel(Base):
    __tablename__ = "suspected_attackers"

    id = Column(Integer, primary_key=True, index=True)
    src_ip = Column(String(64), unique=True, index=True, nullable=False)
    severity = Column(String(32), nullable=True)
    first_seen = Column(DateTime(timezone=True), nullable=True)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class UserModel(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(128), unique=True, index=True, nullable=False)
    # 预留字段：后续接入登录鉴权时可存储密码哈希（不存明文）。
    password_hash = Column(Text, nullable=True)
    # 角色：admin / readonly
    role = Column(String(32), index=True, nullable=False, default="readonly")
    is_active = Column(Boolean, default=True)
    last_login_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
