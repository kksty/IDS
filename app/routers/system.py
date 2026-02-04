# -*- coding: utf-8 -*-
"""系统控制路由器"""

from fastapi import APIRouter, HTTPException
from typing import Dict, Any

from app.services.system_manager import get_system_manager

router = APIRouter(prefix="/api/system", tags=["system"])

@router.get("/status")
async def get_system_status() -> Dict[str, Any]:
    """获取系统状态"""
    manager = get_system_manager()
    return manager.get_status()

@router.post("/sniffer/start")
async def start_sniffer() -> Dict[str, str]:
    """启动网络嗅探器"""
    manager = get_system_manager()
    success = manager.start_sniffer()
    if success:
        return {"message": "Sniffer started successfully"}
    else:
        raise HTTPException(status_code=500, detail="Failed to start sniffer")

@router.post("/sniffer/stop")
async def stop_sniffer() -> Dict[str, str]:
    """停止网络嗅探器"""
    manager = get_system_manager()
    success = manager.stop_sniffer()
    if success:
        return {"message": "Sniffer stopped successfully"}
    else:
        raise HTTPException(status_code=500, detail="Failed to stop sniffer")