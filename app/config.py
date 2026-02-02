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