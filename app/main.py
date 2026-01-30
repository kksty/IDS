import threading
import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.routers import rules, websocket
from app.routers import metrics as metrics_router
from app.routers import alerts as alerts_router
from app.services.sniffer import start_sniffing


# 定义生命周期管理器
@asynccontextmanager
async def lifespan(app: FastAPI):
    # 获取 FastAPI 真正的主 Loop
    main_loop = asyncio.get_running_loop() 
    
    # ！！！在这里手动指定网卡名！！！
    # 例如：target_iface = "eth0" 或 "lo"
    target_iface = "lo" # 保持 None 则使用默认网卡
    # 初始化数据库表并加载规则到内存引擎（若配置了 DB）
    # 强制初始化数据库并加载规则；若失败应当让服务启动失败以便尽早发现配置问题
    from app.db import init_db
    from app.services import engine as engine_mgr
    init_db()
    engine_mgr.load_rules_from_db()
    
    # 将 websocket manager 的 broadcast 显式传入嗅探线程，避免在子线程中导入导致的循环依赖
    sniffer_thread = threading.Thread(
        target=start_sniffing,
        args=(target_iface, main_loop, websocket.manager.broadcast),
        daemon=True,
    )
    sniffer_thread.start()
    
    print(f"[*] Lifespan: Sniffer thread tied to loop {id(main_loop)}", flush=True)
    yield


import os

# 简单日志配置（在生产中可替换为更复杂的配置）
log_level = os.getenv("IDS_LOG_LEVEL", "INFO")
logging.basicConfig(
    level=getattr(logging, log_level.upper(), logging.INFO),
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)

app = FastAPI(title="Python IDS Backend", version="0.1.0", lifespan=lifespan)


# 配置 CORS (允许 Vue 前端访问)
app.add_middleware(

    CORSMiddleware,
    allow_origins=["*"],  # 开发阶段允许所有来源，生产环境改为 ["http://localhost:8080"]
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 注册路由
app.include_router(rules.router)
app.include_router(websocket.router)
app.include_router(metrics_router.router)
app.include_router(alerts_router.router)

@app.get("/")
def root():
    return {"message": "IDS Backend is running"}



if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)