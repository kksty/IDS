# -*- coding: utf-8 -*-
import os
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker, declarative_base

# 使用统一的配置管理
from app.config import config

DATABASE_URL = config.DATABASE_URL

if not DATABASE_URL:
    raise RuntimeError(
        "IDS_DATABASE_URL is not set. Configure PostgreSQL DSN, e.g. 'postgresql+psycopg2://user:pw@host:5432/ids'"
    )

# 数据库连接池配置
connect_args = {}
engine = create_engine(
    DATABASE_URL,
    connect_args=connect_args,
    pool_pre_ping=True,
    pool_size=config.DB_POOL_SIZE,
    max_overflow=config.DB_MAX_OVERFLOW,
    pool_timeout=config.DB_POOL_TIMEOUT,
    pool_recycle=config.DB_POOL_RECYCLE
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def init_db():
    """Create database tables (idempotent)."""
    Base.metadata.create_all(bind=engine)
    # lightweight schema evolution for new alert columns
    try:
        insp = inspect(engine)
        if "alerts" in insp.get_table_names():
            cols = {c["name"] for c in insp.get_columns("alerts")}
            with engine.begin() as conn:
                if "priority" not in cols:
                    conn.execute(text("ALTER TABLE alerts ADD COLUMN priority INTEGER"))
                if "severity" not in cols:
                    conn.execute(text("ALTER TABLE alerts ADD COLUMN severity VARCHAR(16)"))
    except Exception:
        # ignore schema evolution errors to avoid startup failure
        pass
