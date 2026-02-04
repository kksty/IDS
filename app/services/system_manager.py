# -*- coding: utf-8 -*-
"""系统管理器 - 控制IDS组件的启动和停止"""

import asyncio
import threading
import logging
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

    def set_event_loop(self, loop: asyncio.AbstractEventLoop):
        """设置事件循环"""
        self.event_loop = loop

    def set_broadcast_callable(self, broadcast_callable):
        """设置广播回调函数"""
        self.broadcast_callable = broadcast_callable

    def get_status(self) -> Dict[str, Any]:
        """获取系统状态"""
        return {
            "sniffer_active": self.sniffer_thread is not None and self.sniffer_thread.is_alive(),
            "correlation_monitor_active": hasattr(self, '_correlation_started') and self._correlation_started
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


_system_manager = SystemManager()

def get_system_manager() -> SystemManager:
    """获取系统管理器实例"""
    return _system_manager