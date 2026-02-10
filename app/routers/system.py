# -*- coding: utf-8 -*-
"""系统控制路由器"""

import asyncio
from fastapi import APIRouter, HTTPException
from typing import Dict, Any, Optional
from pydantic import BaseModel

from app.services.system_manager import get_system_manager

router = APIRouter(prefix="/api/system", tags=["system"])


class PcapAnalyzeRequest(BaseModel):
    path: str
    max_packets: Optional[int] = None

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


@router.post("/behavior/start")
async def start_behavior() -> Dict[str, str]:
    """启动行为分析"""
    manager = get_system_manager()
    success = manager.set_behavior_enabled(True)
    if success:
        return {"message": "Behavior analysis started"}
    raise HTTPException(status_code=500, detail="Failed to start behavior analysis")


@router.post("/behavior/stop")
async def stop_behavior() -> Dict[str, str]:
    """停止行为分析"""
    manager = get_system_manager()
    success = manager.set_behavior_enabled(False)
    if success:
        return {"message": "Behavior analysis stopped"}
    raise HTTPException(status_code=500, detail="Failed to stop behavior analysis")


@router.post("/pcap/analyze")
async def analyze_pcap(req: PcapAnalyzeRequest) -> Dict[str, Any]:
    """离线分析 PCAP 文件（后台任务）"""
    manager = get_system_manager()
    try:
        job_id = manager.start_pcap_job(req.path, req.max_packets)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"PCAP analysis failed: {exc}") from exc
    return {"message": "PCAP analysis started", "job_id": job_id}


@router.get("/pcap/status/{job_id}")
async def get_pcap_status(job_id: str) -> Dict[str, Any]:
    """获取 PCAP 分析任务状态"""
    manager = get_system_manager()
    job = manager.get_pcap_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="PCAP job not found")
    return job


@router.post("/pcap/stop/{job_id}")
async def stop_pcap_job(job_id: str) -> Dict[str, Any]:
    """停止 PCAP 分析任务"""
    manager = get_system_manager()
    ok = manager.stop_pcap_job(job_id)
    if not ok:
        raise HTTPException(status_code=404, detail="PCAP job not found")
    return {"message": "PCAP stop requested", "job_id": job_id}