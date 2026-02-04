# -*- coding: utf-8 -*-
"""
IDS 系统配置文件
集中管理所有配置项，支持环境变量覆盖
"""
import os
from typing import Optional

# 加载环境变量（如果存在 .env 文件）
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # dotenv 不是必需的依赖


class Config:
    """应用配置管理"""

    # 默认值常量
    DEFAULT_NETWORK_INTERFACE = "lo"
    DEFAULT_HOST = "0.0.0.0"
    DEFAULT_PORT = 8000
    DEFAULT_LOG_LEVEL = "INFO"
    DEFAULT_CONTEXT_TIMEOUT = 300.0
    DEFAULT_MAX_BUFFER_SIZE = 256 * 1024  # 256KB
    DEFAULT_DB_POOL_SIZE = 10
    DEFAULT_DB_MAX_OVERFLOW = 20
    DEFAULT_DB_POOL_TIMEOUT = 30
    DEFAULT_DB_POOL_RECYCLE = 3600
    
    # 行为分析默认配置
    DEFAULT_CONNECTION_WINDOW_SIZE = 60
    DEFAULT_MAX_CONNECTIONS_PER_WINDOW = 200  # 增加阈值以减少正常访问的误报
    DEFAULT_PORT_SCAN_WINDOW = 300
    DEFAULT_PORT_SCAN_THRESHOLD = 40
    DEFAULT_PORT_SCAN_MIN_TARGETS = 5
    DEFAULT_PORT_SCAN_MIN_PORTS = 40
    DEFAULT_MAX_AUTH_FAILURES = 5
    DEFAULT_AUTH_WINDOW_SIZE = 300
    DEFAULT_SAMPLE_INTERVAL = 1.0
    DEFAULT_EWMA_ALPHA = 0.2
    DEFAULT_SPIKE_FACTOR_PACKETS = 5.0
    DEFAULT_SPIKE_FACTOR_BYTES = 5.0
    DEFAULT_SUSTAIN_WINDOWS = 3
    DEFAULT_WARMUP_WINDOWS = 30
    DEFAULT_SESSION_TIMEOUT = 3600
    DEFAULT_DEDUPE_WINDOW = 10
    DEFAULT_BEHAVIOR_ALERT_COOLDOWN = 120
    DEFAULT_PORT_SCAN_ALERT_COOLDOWN = 180
    DEFAULT_HIGH_CONN_ALERT_COOLDOWN = 120

    # 关联分析默认配置
    DEFAULT_CORR_WINDOW_SIZE = 600
    DEFAULT_CORR_MIN_RULE_DIVERSITY = 4
    DEFAULT_CORR_MIN_ALERTS = 8
    DEFAULT_CORR_BEHAVIOR_WEIGHT = 1
    DEFAULT_CORR_ALERT_COOLDOWN = 300

    # 网络配置
    NETWORK_INTERFACE: str = os.getenv("IDS_NETWORK_INTERFACE", DEFAULT_NETWORK_INTERFACE)

    # 服务器配置
    HOST: str = os.getenv("IDS_HOST", DEFAULT_HOST)
    PORT: int = int(os.getenv("IDS_PORT", str(DEFAULT_PORT)))
    RELOAD: bool = os.getenv("IDS_RELOAD", "false").lower() == "true"

    # 日志配置
    LOG_LEVEL: str = os.getenv("IDS_LOG_LEVEL", DEFAULT_LOG_LEVEL)
    LOG_FORMAT: str = os.getenv("IDS_LOG_FORMAT", "%(asctime)s %(levelname)s [%(name)s] %(message)s")
    LOG_TO_FILE: bool = os.getenv("IDS_LOG_TO_FILE", "false").lower() == "true"

    # 数据库配置（通过环境变量设置）
    DATABASE_URL: Optional[str] = os.getenv("IDS_DATABASE_URL")

    # 嗅探配置
    CONTEXT_TIMEOUT: float = float(os.getenv("IDS_CONTEXT_TIMEOUT", str(DEFAULT_CONTEXT_TIMEOUT)))
    MAX_BUFFER_SIZE: int = int(os.getenv("IDS_MAX_BUFFER_SIZE", str(DEFAULT_MAX_BUFFER_SIZE)))
    
    # 行为分析配置
    CONNECTION_WINDOW_SIZE: int = int(os.getenv("IDS_CONNECTION_WINDOW_SIZE", str(DEFAULT_CONNECTION_WINDOW_SIZE)))
    MAX_CONNECTIONS_PER_WINDOW: int = int(os.getenv("IDS_MAX_CONNECTIONS_PER_WINDOW", str(DEFAULT_MAX_CONNECTIONS_PER_WINDOW)))
    PORT_SCAN_WINDOW: int = int(os.getenv("IDS_PORT_SCAN_WINDOW", str(DEFAULT_PORT_SCAN_WINDOW)))
    PORT_SCAN_THRESHOLD: int = int(os.getenv("IDS_PORT_SCAN_THRESHOLD", str(DEFAULT_PORT_SCAN_THRESHOLD)))
    PORT_SCAN_MIN_TARGETS: int = int(os.getenv("IDS_PORT_SCAN_MIN_TARGETS", str(DEFAULT_PORT_SCAN_MIN_TARGETS)))
    PORT_SCAN_MIN_PORTS: int = int(os.getenv("IDS_PORT_SCAN_MIN_PORTS", str(DEFAULT_PORT_SCAN_MIN_PORTS)))
    MAX_AUTH_FAILURES: int = int(os.getenv("IDS_MAX_AUTH_FAILURES", str(DEFAULT_MAX_AUTH_FAILURES)))
    AUTH_WINDOW_SIZE: int = int(os.getenv("IDS_AUTH_WINDOW_SIZE", str(DEFAULT_AUTH_WINDOW_SIZE)))
    SAMPLE_INTERVAL: float = float(os.getenv("IDS_SAMPLE_INTERVAL", str(DEFAULT_SAMPLE_INTERVAL)))
    EWMA_ALPHA: float = float(os.getenv("IDS_EWMA_ALPHA", str(DEFAULT_EWMA_ALPHA)))
    SPIKE_FACTOR_PACKETS: float = float(os.getenv("IDS_SPIKE_FACTOR_PACKETS", str(DEFAULT_SPIKE_FACTOR_PACKETS)))
    SPIKE_FACTOR_BYTES: float = float(os.getenv("IDS_SPIKE_FACTOR_BYTES", str(DEFAULT_SPIKE_FACTOR_BYTES)))
    SUSTAIN_WINDOWS: int = int(os.getenv("IDS_SUSTAIN_WINDOWS", str(DEFAULT_SUSTAIN_WINDOWS)))
    WARMUP_WINDOWS: int = int(os.getenv("IDS_WARMUP_WINDOWS", str(DEFAULT_WARMUP_WINDOWS)))
    SESSION_TIMEOUT: int = int(os.getenv("IDS_SESSION_TIMEOUT", str(DEFAULT_SESSION_TIMEOUT)))
    DEDUPE_WINDOW: int = int(os.getenv("IDS_DEDUPE_WINDOW", str(DEFAULT_DEDUPE_WINDOW)))
    BEHAVIOR_ALERT_COOLDOWN: int = int(os.getenv("IDS_BEHAVIOR_ALERT_COOLDOWN", str(DEFAULT_BEHAVIOR_ALERT_COOLDOWN)))
    PORT_SCAN_ALERT_COOLDOWN: int = int(os.getenv("IDS_PORT_SCAN_ALERT_COOLDOWN", str(DEFAULT_PORT_SCAN_ALERT_COOLDOWN)))
    HIGH_CONN_ALERT_COOLDOWN: int = int(os.getenv("IDS_HIGH_CONN_ALERT_COOLDOWN", str(DEFAULT_HIGH_CONN_ALERT_COOLDOWN)))

    CORR_WINDOW_SIZE: int = int(os.getenv("IDS_CORR_WINDOW_SIZE", str(DEFAULT_CORR_WINDOW_SIZE)))
    CORR_MIN_RULE_DIVERSITY: int = int(os.getenv("IDS_CORR_MIN_RULE_DIVERSITY", str(DEFAULT_CORR_MIN_RULE_DIVERSITY)))
    CORR_MIN_ALERTS: int = int(os.getenv("IDS_CORR_MIN_ALERTS", str(DEFAULT_CORR_MIN_ALERTS)))
    CORR_BEHAVIOR_WEIGHT: int = int(os.getenv("IDS_CORR_BEHAVIOR_WEIGHT", str(DEFAULT_CORR_BEHAVIOR_WEIGHT)))
    CORR_ALERT_COOLDOWN: int = int(os.getenv("IDS_CORR_ALERT_COOLDOWN", str(DEFAULT_CORR_ALERT_COOLDOWN)))

    # 性能配置
    DB_POOL_SIZE: int = int(os.getenv("IDS_DB_POOL_SIZE", str(DEFAULT_DB_POOL_SIZE)))
    DB_MAX_OVERFLOW: int = int(os.getenv("IDS_DB_MAX_OVERFLOW", str(DEFAULT_DB_MAX_OVERFLOW)))
    DB_POOL_TIMEOUT: int = int(os.getenv("IDS_DB_POOL_TIMEOUT", str(DEFAULT_DB_POOL_TIMEOUT)))
    DB_POOL_RECYCLE: int = int(os.getenv("IDS_DB_POOL_RECYCLE", str(DEFAULT_DB_POOL_RECYCLE)))

    @classmethod
    def validate(cls):
        """验证配置"""
        errors = []

        # 必需配置检查
        if not cls.DATABASE_URL:
            errors.append("IDS_DATABASE_URL is required")

        # 端口范围检查
        if cls.PORT < 1 or cls.PORT > 65535:
            errors.append(f"Invalid port number: {cls.PORT} (must be 1-65535)")

        # 超时时间检查
        if cls.CONTEXT_TIMEOUT <= 0:
            errors.append(f"Invalid context timeout: {cls.CONTEXT_TIMEOUT} (must be > 0)")

        # 缓冲区大小检查
        if cls.MAX_BUFFER_SIZE <= 0:
            errors.append(f"Invalid max buffer size: {cls.MAX_BUFFER_SIZE} (must be > 0)")

        # 行为分析配置检查
        if cls.CONNECTION_WINDOW_SIZE <= 0:
            errors.append(f"Invalid connection window size: {cls.CONNECTION_WINDOW_SIZE} (must be > 0)")
        if cls.MAX_CONNECTIONS_PER_WINDOW <= 0:
            errors.append(f"Invalid max connections per window: {cls.MAX_CONNECTIONS_PER_WINDOW} (must be > 0)")
        if cls.PORT_SCAN_WINDOW <= 0:
            errors.append(f"Invalid port scan window: {cls.PORT_SCAN_WINDOW} (must be > 0)")
        if cls.PORT_SCAN_THRESHOLD <= 0:
            errors.append(f"Invalid port scan threshold: {cls.PORT_SCAN_THRESHOLD} (must be > 0)")
        if cls.MAX_AUTH_FAILURES <= 0:
            errors.append(f"Invalid max auth failures: {cls.MAX_AUTH_FAILURES} (must be > 0)")
        if cls.AUTH_WINDOW_SIZE <= 0:
            errors.append(f"Invalid auth window size: {cls.AUTH_WINDOW_SIZE} (must be > 0)")
        if cls.SAMPLE_INTERVAL <= 0:
            errors.append(f"Invalid sample interval: {cls.SAMPLE_INTERVAL} (must be > 0)")
        if cls.EWMA_ALPHA <= 0 or cls.EWMA_ALPHA > 1:
            errors.append(f"Invalid EWMA alpha: {cls.EWMA_ALPHA} (must be 0-1)")
        if cls.SPIKE_FACTOR_PACKETS <= 0:
            errors.append(f"Invalid spike factor packets: {cls.SPIKE_FACTOR_PACKETS} (must be > 0)")
        if cls.SPIKE_FACTOR_BYTES <= 0:
            errors.append(f"Invalid spike factor bytes: {cls.SPIKE_FACTOR_BYTES} (must be > 0)")
        if cls.SUSTAIN_WINDOWS <= 0:
            errors.append(f"Invalid sustain windows: {cls.SUSTAIN_WINDOWS} (must be > 0)")
        if cls.WARMUP_WINDOWS <= 0:
            errors.append(f"Invalid warmup windows: {cls.WARMUP_WINDOWS} (must be > 0)")
        if cls.SESSION_TIMEOUT <= 0:
            errors.append(f"Invalid session timeout: {cls.SESSION_TIMEOUT} (must be > 0)")
        if cls.DEDUPE_WINDOW <= 0:
            errors.append(f"Invalid dedupe window: {cls.DEDUPE_WINDOW} (must be > 0)")

        # 数据库连接池参数检查
        if cls.DB_POOL_SIZE <= 0:
            errors.append(f"Invalid DB pool size: {cls.DB_POOL_SIZE} (must be > 0)")
        if cls.DB_MAX_OVERFLOW < 0:
            errors.append(f"Invalid DB max overflow: {cls.DB_MAX_OVERFLOW} (must be >= 0)")
        if cls.DB_POOL_TIMEOUT <= 0:
            errors.append(f"Invalid DB pool timeout: {cls.DB_POOL_TIMEOUT} (must be > 0)")
        if cls.DB_POOL_RECYCLE <= 0:
            errors.append(f"Invalid DB pool recycle: {cls.DB_POOL_RECYCLE} (must be > 0)")

        # 日志级别检查
        valid_log_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        if cls.LOG_LEVEL.upper() not in valid_log_levels:
            errors.append(f"Invalid log level: {cls.LOG_LEVEL} (must be one of {valid_log_levels})")

        if errors:
            raise ValueError("Configuration validation failed:\n" + "\n".join(f"  - {error}" for error in errors))

        return True


# 全局配置实例
config = Config()