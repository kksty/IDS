# -*- coding: utf-8 -*-
"""系统管理器 - 控制IDS组件的启动和停止"""

import asyncio
import threading
import logging
import os
import time
import uuid
from typing import Optional, Dict, Any

from app.services.sniffer import SnifferManager
from app.services.correlation_monitor import start_correlation_monitor, stop_correlation_monitor
from app.config import config

logger = logging.getLogger("ids.system_manager")

class SystemManager:
    """IDS系统管理器"""

    def __init__(self):
        self.sniffer_manager: Optional[SnifferManager] = None
        self.sniffer_thread: Optional[threading.Thread] = None
        self.event_loop: Optional[asyncio.AbstractEventLoop] = None
        self.broadcast_callable = None
        self._lock = threading.Lock()
        self._correlation_started = False
        self._pcap_jobs: Dict[str, Dict[str, Any]] = {}
        self._pcap_lock = threading.Lock()

    def set_event_loop(self, loop: asyncio.AbstractEventLoop):
        """设置事件循环"""
        self.event_loop = loop

    def set_broadcast_callable(self, broadcast_callable):
        """设置广播回调函数"""
        self.broadcast_callable = broadcast_callable

    def get_status(self) -> Dict[str, Any]:
        """获取系统状态"""
        try:
            from app.services.behavior_analyzer import get_behavior_analyzer
            behavior_enabled = get_behavior_analyzer().is_enabled()
        except Exception:
            behavior_enabled = True
        return {
            "sniffer_active": self.sniffer_thread is not None and self.sniffer_thread.is_alive(),
            "correlation_monitor_active": hasattr(self, '_correlation_started') and self._correlation_started,
            "behavior_enabled": behavior_enabled,
        }

    def start_sniffer(self) -> bool:
        """单独启动嗅探器"""
        with self._lock:
            if self.sniffer_thread is not None and self.sniffer_thread.is_alive():
                logger.warning("Sniffer is already running")
                return False

            try:
                logger.info("Starting network sniffer...")

                # 初始化嗅探管理器（如果还没有）
                if not self.sniffer_manager:
                    self.sniffer_manager = SnifferManager()
                    if self.event_loop:
                        self.sniffer_manager.set_loop(self.event_loop)

                # 启动嗅探线程
                target_iface = config.NETWORK_INTERFACE
                self.sniffer_thread = threading.Thread(
                    target=self._start_sniffing,
                    args=(target_iface,),
                    daemon=True,
                    name="NetworkSniffer"
                )
                self.sniffer_thread.start()

                logger.info("Network sniffer started successfully")
                return True

            except Exception as e:
                logger.error(f"Failed to start sniffer: {e}")
                return False

    def stop_sniffer(self) -> bool:
        """单独停止嗅探器"""
        with self._lock:
            if self.sniffer_thread is None or not self.sniffer_thread.is_alive():
                logger.warning("Sniffer is not running")
                return False

            try:
                logger.info("Stopping network sniffer...")

                # 停止嗅探管理器
                if self.sniffer_manager:
                    self.sniffer_manager.stop()

                # 等待嗅探线程结束
                if self.sniffer_thread and self.sniffer_thread.is_alive():
                    self.sniffer_thread.join(timeout=2.0)
                    if self.sniffer_thread.is_alive():
                        logger.warning("Sniffer thread did not stop gracefully")

                self.sniffer_thread = None
                logger.info("Network sniffer stopped successfully")
                return True

            except Exception as e:
                logger.error(f"Failed to stop sniffer: {e}")
                return False

    def _start_sniffing(self, interface: str):
        """启动网络嗅探（在单独线程中运行）"""
        try:
            from app.services.sniffer import start_sniffing
            start_sniffing(
                interface=interface,
                loop=self.event_loop,
                broadcast_callable=self.broadcast_callable,
                manager=self.sniffer_manager
            )
        except Exception as e:
            logger.error(f"Sniffer thread error: {e}")

    def start_correlation_monitor(self) -> bool:
        """启动关联监控"""
        with self._lock:
            if self._correlation_started:
                return False
            try:
                start_correlation_monitor()
                self._correlation_started = True
                return True
            except Exception as e:
                logger.error(f"Start correlation monitor error: {e}")
                return False

    def stop_correlation_monitor(self) -> bool:
        """停止关联监控"""
        with self._lock:
            if not self._correlation_started:
                return False
            try:
                stop_correlation_monitor()
                self._correlation_started = False
                return True
            except Exception as e:
                logger.error(f"Stop correlation monitor error: {e}")
                return False

    def set_behavior_enabled(self, enabled: bool) -> bool:
        """开启/关闭行为分析"""
        try:
            from app.services.behavior_analyzer import get_behavior_analyzer
            get_behavior_analyzer().set_enabled(enabled)
            return True
        except Exception as e:
            logger.error(f"Set behavior enabled failed: {e}")
            return False

    def analyze_pcap(self, pcap_path: str, max_packets: Optional[int] = None) -> int:
        """离线分析 PCAP 文件，复用在线规则链路。"""
        if not pcap_path:
            raise ValueError("pcap_path is required")
        if not os.path.exists(pcap_path):
            raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

        # 初始化嗅探管理器（如果还没有）
        if not self.sniffer_manager:
            self.sniffer_manager = SnifferManager()
            if self.event_loop:
                self.sniffer_manager.set_loop(self.event_loop)

        from app.services.sniffer import process_pcap
        return process_pcap(
            pcap_path,
            loop=self.event_loop,
            manager=self.sniffer_manager,
            broadcast_callable=self.broadcast_callable,
            max_packets=max_packets,
        )

    def start_pcap_job(self, pcap_path: str, max_packets: Optional[int] = None) -> str:
        """启动离线 PCAP 分析任务（后台线程）。"""
        if not pcap_path:
            raise ValueError("pcap_path is required")
        if not os.path.exists(pcap_path):
            raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

        # 初始化嗅探管理器（如果还没有）
        if not self.sniffer_manager:
            self.sniffer_manager = SnifferManager()
            if self.event_loop:
                self.sniffer_manager.set_loop(self.event_loop)

        job_id = uuid.uuid4().hex
        stop_event = threading.Event()
        job = {
            "id": job_id,
            "path": pcap_path,
            "max_packets": max_packets,
            "status": "running",
            "processed": 0,
            "rate": 0.0,
            "started_at": time.time(),
            "ended_at": None,
            "error": None,
            "stop_event": stop_event,
        }

        with self._pcap_lock:
            self._pcap_jobs[job_id] = job

        thread = threading.Thread(
            target=self._run_pcap_job,
            args=(job_id,),
            daemon=True,
            name=f"PCAPJob-{job_id[:8]}",
        )
        thread.start()
        return job_id

    def get_pcap_job(self, job_id: str) -> Optional[Dict[str, Any]]:
        """获取 PCAP 任务状态。"""
        with self._pcap_lock:
            job = self._pcap_jobs.get(job_id)
            if not job:
                return None
            return {
                "id": job.get("id"),
                "path": job.get("path"),
                "max_packets": job.get("max_packets"),
                "status": job.get("status"),
                "processed": job.get("processed"),
                "rate": job.get("rate"),
                "started_at": job.get("started_at"),
                "ended_at": job.get("ended_at"),
                "error": job.get("error"),
            }

    def stop_pcap_job(self, job_id: str) -> bool:
        """请求停止 PCAP 任务。"""
        with self._pcap_lock:
            job = self._pcap_jobs.get(job_id)
            if not job:
                return False
            stop_event = job.get("stop_event")
            if isinstance(stop_event, threading.Event):
                stop_event.set()
            return True

    def _run_pcap_job(self, job_id: str) -> None:
        with self._pcap_lock:
            job = self._pcap_jobs.get(job_id)
        if not job:
            return

        def progress_callback(count: int, rate: float, elapsed: float) -> None:
            with self._pcap_lock:
                j = self._pcap_jobs.get(job_id)
                if not j:
                    return
                j["processed"] = count
                j["rate"] = rate

        stop_event = job.get("stop_event")
        try:
            from app.services.sniffer import process_pcap

            processed = process_pcap(
                job["path"],
                loop=self.event_loop,
                manager=self.sniffer_manager,
                broadcast_callable=self.broadcast_callable,
                max_packets=job.get("max_packets"),
                progress_callback=progress_callback,
                stop_event=stop_event if isinstance(stop_event, threading.Event) else None,
            )
            with self._pcap_lock:
                j = self._pcap_jobs.get(job_id)
                if not j:
                    return
                if isinstance(stop_event, threading.Event) and stop_event.is_set():
                    j["status"] = "stopped"
                else:
                    j["status"] = "completed"
                j["processed"] = processed
                j["ended_at"] = time.time()
        except Exception as exc:
            with self._pcap_lock:
                j = self._pcap_jobs.get(job_id)
                if not j:
                    return
                j["status"] = "failed"
                j["error"] = str(exc)
                j["ended_at"] = time.time()


_system_manager = SystemManager()

def get_system_manager() -> SystemManager:
    """获取系统管理器实例"""
    return _system_manager