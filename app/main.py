import os
import logging
from contextlib import asynccontextmanager
from typing import Optional
from pathlib import Path

import asyncio
import threading

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.routers import rules, websocket
from app.routers import metrics as metrics_router
from app.routers import alerts as alerts_router
from app.services.sniffer import start_sniffing
from app.config import config


def setup_logging():
    """配置日志系统"""
    # 验证配置
    try:
        config.validate()
    except ValueError as e:
        print(f"Configuration error: {e}")
        raise

    # 创建日志目录
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)

    handlers = [logging.StreamHandler()]

    if config.LOG_TO_FILE:
        log_file = log_dir / "ids.log"
        handlers.append(
            logging.FileHandler(log_file, encoding='utf-8')
        )

    # 设置根日志器级别
    logging.basicConfig(
        level=getattr(logging, config.LOG_LEVEL.upper(), logging.INFO),
        format=config.LOG_FORMAT,
        handlers=handlers
    )

    # 单独配置 uvicorn 日志级别，避免过多 HTTP 调试信息
    uvicorn_logger = logging.getLogger("uvicorn")
    uvicorn_access_logger = logging.getLogger("uvicorn.access")
    
    # 在生产环境，降低 uvicorn 的日志级别
    if not config.RELOAD and config.LOG_LEVEL.upper() != "DEBUG":
        uvicorn_logger.setLevel(logging.INFO)
        uvicorn_access_logger.setLevel(logging.WARNING)  # 不显示访问日志
    else:
        # 开发环境保持 DEBUG，但过滤掉过多细节
        uvicorn_logger.setLevel(logging.INFO)
        uvicorn_access_logger.setLevel(logging.WARNING)


def get_network_interface() -> str:
    """获取网络接口配置"""
    return config.NETWORK_INTERFACE


@asynccontextmanager
async def lifespan(app: FastAPI):
    """应用生命周期管理器"""
    logger = logging.getLogger(__name__)

    try:
        # 启动事件
        logger.info("IDS Backend starting up...")
        logger.info(f"Configuration: HOST={config.HOST}, PORT={config.PORT}, LOG_LEVEL={config.LOG_LEVEL}")
        logger.info(f"Network interface: {config.NETWORK_INTERFACE}")
        logger.info(f"Database configured: {bool(config.DATABASE_URL)}")

        # 获取配置
        target_iface = config.NETWORK_INTERFACE
        main_loop = asyncio.get_running_loop()

        logger.info(f"Starting IDS with network interface: {target_iface}")

        # 初始化数据库和规则引擎
        from app.db import init_db
        from app.services import engine as engine_mgr

        init_db()
        engine_mgr.load_rules_from_db()

        # 启动网络嗅探线程
        sniffer_thread = threading.Thread(
            target=start_sniffing,
            args=(target_iface, main_loop, websocket.manager.broadcast),
            daemon=True,
            name="NetworkSniffer"
        )
        sniffer_thread.start()

        logger.info(f"Sniffer thread started on interface {target_iface}")

        yield

    except Exception as e:
        logger.error(f"Failed to initialize application: {e}")
        raise
    finally:
        # 关闭事件
        logger.info("IDS Backend shutting down...")


# 设置日志
setup_logging()

# 创建FastAPI应用
app = FastAPI(
    title="IDS Dashboard API",
    description="Intrusion Detection System with real-time monitoring",
    version="1.0.0",
    lifespan=lifespan
)

# 配置CORS - 生产环境应该限制允许的源
allowed_origins = [
    "http://localhost:3000",  # React dev server
    "http://localhost:8080",  # Vue dev server
    "http://127.0.0.1:3000",
    "http://127.0.0.1:8080",
]

# 在开发环境中允许所有本地源
if config.RELOAD or os.getenv("ENV") == "development":
    allowed_origins.append("*")

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 注册路由
app.include_router(rules.router)
app.include_router(websocket.router)
app.include_router(metrics_router.router)
app.include_router(alerts_router.router)


@app.get("/health")
async def health_check():
    """健康检查端点"""
    import time

    try:
        # 基本健康信息
        health_info = {
            "status": "healthy",
            "timestamp": time.time(),
            "version": app.version,
        }

        # 检查数据库连接
        try:
            from app.db import SessionLocal
            from sqlalchemy import text
            session = SessionLocal()
            session.execute(text("SELECT 1"))
            session.close()
            health_info["database"] = "connected"
        except Exception as e:
            health_info["database"] = f"error: {str(e)}"
            health_info["status"] = "degraded"

        # 检查配置
        try:
            config.validate()
            health_info["configuration"] = "valid"
        except Exception as e:
            health_info["configuration"] = f"invalid: {str(e)}"
            health_info["status"] = "unhealthy"

        return health_info

    except Exception as e:
        return {
            "status": "unhealthy",
            "error": str(e),
            "timestamp": time.time()
        }


@app.get("/")
def root():
    return {"message": "IDS Backend is running"}


@app.get("/config")
async def get_config():
    """获取当前配置（调试用）"""
    return {
        "network_interface": config.NETWORK_INTERFACE,
        "host": config.HOST,
        "port": config.PORT,
        "log_level": config.LOG_LEVEL,
        "database_configured": bool(config.DATABASE_URL)
    }


if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "app.main:app",
        host=config.HOST,
        port=config.PORT,
        reload=config.RELOAD,
        log_level="info"  # uvicorn 使用 INFO 级别，详细控制由 logging 配置处理
    )