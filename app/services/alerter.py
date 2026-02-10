# -*- coding: utf-8 -*-
import logging
import queue
import threading
import time
from typing import Callable, Optional, Dict, Any, Tuple

from app.db import SessionLocal
from app.models.db_models import AlertModel
from app.metrics import ALERTS_EMITTED

_ALERTER = None

logger = logging.getLogger("ids.alerter")


class Alerter:
    """简单的告警去重与聚合服务。

    行为：
    - 首次收到某 (rule_id, src, dst) 告警时立即持久化并广播。
    - 在窗口期内对同一 key 的后续告警进行计数聚合；定期 flush 时再生成聚合告警并广播/持久化。
    """

    def __init__(self, broadcast_callable: Optional[Callable[[Dict[str, Any]], Any]] = None,
                 loop=None, dedupe_window: int = None, flush_interval: int = 5):
        from app.config import config
        
        self.broadcast_callable = broadcast_callable
        self.loop = loop
        self.dedupe_window = dedupe_window or config.DEDUPE_WINDOW
        self.flush_interval = flush_interval
        self.batch_size = 500
        self.batch_flush_interval = 1.0

        # ensure ALERTS_EMITTED imported
        try:
            from app.metrics import ALERTS_EMITTED
        except Exception:
            pass

        self._lock = threading.Lock()
        # recent alert fingerprints to suppress short-time exact duplicates
        self._recent_alerts: Dict[str, float] = {}

        # 后台工作线程：将慢 I/O（DB 持久化和 WebSocket 广播）从检测/嗅探线程中解耦
        self._queue: "queue.Queue[Dict[str, Any]]" = queue.Queue(maxsize=10000)
        self._stop_event = threading.Event()
        self._worker_thread = threading.Thread(target=self._worker_loop, name="AlerterWorker", daemon=True)
        self._worker_thread.start()

    def set_loop(self, loop):
        """设置事件循环引用"""
        self.loop = loop

    def set_broadcast_callable(self, broadcast_callable: Callable[[Dict[str, Any]], Any]):
        """设置广播回调函数"""
        self.broadcast_callable = broadcast_callable

    def _key(self, alert: Dict[str, Any]) -> Tuple[str, str, str, str]:
        # include match_text/payload context for aggregation
        return (str(alert.get("match_rule")), str(alert.get("src_ip")), str(alert.get("dst_ip")), str(alert.get("match_text")))

    def _sanitize_text(self, val: Any, maxlen: int = 400) -> str:
        if val is None:
            return ""
        # decode bytes if necessary
        if isinstance(val, (bytes, bytearray)):
            try:
                s = val.decode("latin-1", errors="ignore")
            except Exception:
                s = str(val)
        else:
            s = str(val)
        # replace non-ascii/control chars with \xNN for readability
        def _safe_char(ch: str) -> str:
          code = ord(ch)
          if 32 <= code <= 126:
            return ch
          return f"\\x{code:02x}"

        s = "".join(_safe_char(ch) for ch in s)
        # collapse excessive whitespace
        s = " ".join(s.split())
        if len(s) > maxlen:
            s = s[:maxlen] + '…'
        return s

    def handle_alert(self, alert: Dict[str, Any]):
        """接收告警请求：做短时间去重，然后异步入队，由后台线程执行慢 I/O。"""
        # 短时间窗口去重逻辑保持在锁内，保证 _recent_alerts 一致性
        with self._lock:
            # compute fingerprint
            try:
                fp_src = str(alert.get("src_ip") or "")
                fp_dst = str(alert.get("dst_ip") or "")
                fp_rule = str(alert.get("match_rule") or "")
                fp_match = str(alert.get("match_text") or "")
                fp_preview = str(alert.get("payload_preview") or "")
                fp = f"{fp_rule}|{fp_src}|{fp_dst}|{fp_match}|{fp_preview}"
            except Exception:
                fp = None

            now = time.time()
            # cleanup old entries
            try:
                for k, t in list(self._recent_alerts.items()):
                    if now - t > self.dedupe_window:
                        del self._recent_alerts[k]
            except Exception:
                pass

            if fp is not None and fp in self._recent_alerts:
                return

            if fp is not None:
                self._recent_alerts[fp] = now

        # 将告警放入队列，由后台线程处理；队列满时丢弃并记录日志，避免阻塞嗅探线程
        try:
            self._queue.put_nowait(alert)
        except queue.Full:
            logger.warning("Alert queue is full; dropping alert to avoid blocking")

    def _persist(self, alert: Dict[str, Any]):
        try:
            session = SessionLocal()
            # Persist only the match_text and a short preview (通常为 URL 或 packet_summary)，并对文本做脱敏/截断
            mt = self._sanitize_text(alert.get("match_text"), maxlen=400)
            pv = alert.get("payload_preview") if alert.get("payload_preview") is not None else alert.get("packet_summary")
            pv = self._sanitize_text(pv, maxlen=400)
            priority = alert.get("priority")
            severity = alert.get("severity")
            if (severity is None or severity == "") and priority is not None:
                try:
                    pr = int(priority)
                    if pr <= 1:
                        severity = "high"
                    elif pr == 2:
                        severity = "medium"
                    else:
                        severity = "low"
                except Exception:
                    pass
            am = AlertModel(
                rule_id=alert.get("match_rule"),
                match_text=mt,
                src_ip=alert.get("src_ip"),
                dst_ip=alert.get("dst_ip"),
                pos_start=alert.get("pos_start"),
                pos_end=alert.get("pos_end"),
                payload_preview=pv,
                priority=priority,
                severity=severity,
            )
            session.add(am)
            session.commit()
        except Exception:
            print("[alerter] failed to persist alert", flush=True)
        finally:
            try:
                session.close()
            except Exception:
                pass

    def _persist_batch(self, alerts: list[Dict[str, Any]]):
        if not alerts:
            return
        try:
            session = SessionLocal()
            models = []
            for alert in alerts:
                mt = self._sanitize_text(alert.get("match_text"), maxlen=400)
                pv = alert.get("payload_preview") if alert.get("payload_preview") is not None else alert.get("packet_summary")
                pv = self._sanitize_text(pv, maxlen=400)
                priority = alert.get("priority")
                severity = alert.get("severity")
                if (severity is None or severity == "") and priority is not None:
                    try:
                        pr = int(priority)
                        if pr <= 1:
                            severity = "high"
                        elif pr == 2:
                            severity = "medium"
                        else:
                            severity = "low"
                    except Exception:
                        pass
                models.append(
                    AlertModel(
                        rule_id=alert.get("match_rule"),
                        match_text=mt,
                        src_ip=alert.get("src_ip"),
                        dst_ip=alert.get("dst_ip"),
                        pos_start=alert.get("pos_start"),
                        pos_end=alert.get("pos_end"),
                        payload_preview=pv,
                        priority=priority,
                        severity=severity,
                    )
                )
            session.bulk_save_objects(models)
            session.commit()
        except Exception:
            print("[alerter] failed to persist alert batch", flush=True)
        finally:
            try:
                session.close()
            except Exception:
                pass

    def _broadcast(self, alert: Dict[str, Any]):
        # broadcast without short-time suppression
        try:
            if self.loop is None:
                logger.warning("No loop available for broadcasting")
                return
            if not getattr(self.loop, 'is_running', lambda: False)():
                logger.warning("Event loop not running; cannot broadcast")
                return
            if self.broadcast_callable is None:
                logger.warning("No broadcast_callable configured; cannot broadcast")
                return

            # sanitize fields before sending over websocket to avoid binary/control chars breaking UI
            safe = dict(alert)
            for k in ("packet_summary", "match_text", "payload_preview", "timestamp", "details"):
                if k in safe:
                    try:
                        if k == "details" and isinstance(safe[k], dict):
                            # 特殊处理details字段，保持其结构
                            safe[k] = {key: self._sanitize_text(str(val)) for key, val in safe[k].items()}
                        else:
                            safe[k] = self._sanitize_text(safe[k])
                    except Exception:
                        safe[k] = ""
            import asyncio

            coro = None
            try:
                coro = self.broadcast_callable(safe)
            except Exception:
                logger.exception("broadcast_callable raised when called")
                raise

            try:
                asyncio.run_coroutine_threadsafe(coro, self.loop)
            except Exception:
                logger.exception("Failed to schedule broadcast coroutine")
        except Exception:
            logger.exception("Unexpected error in _broadcast")

    def _worker_loop(self):
        """后台工作线程：从队列中取出告警并执行持久化和广播。"""
        buffer: list[Dict[str, Any]] = []
        last_flush = time.time()
        while not self._stop_event.is_set():
            try:
                alert = self._queue.get(timeout=0.5)
            except queue.Empty:
                alert = None

            if alert is not None:
                try:
                    try:
                        self._broadcast(alert)
                    except Exception:
                        logger.exception("Failed to broadcast alert")
                    try:
                        ALERTS_EMITTED.inc()
                    except Exception:
                        logger.exception("Failed to increment ALERTS_EMITTED")
                    try:
                        # 如果是行为分析告警，增加专门的计数器
                        if alert.get("match_type") == "behavior":
                            from app.metrics import BEHAVIOR_ALERTS_EMITTED
                            BEHAVIOR_ALERTS_EMITTED.inc()
                    except Exception:
                        logger.exception("Failed to increment BEHAVIOR_ALERTS_EMITTED")
                    buffer.append(alert)
                finally:
                    try:
                        self._queue.task_done()
                    except Exception:
                        pass

            now = time.time()
            if buffer and (
                len(buffer) >= self.batch_size
                or now - last_flush >= self.batch_flush_interval
            ):
                try:
                    self._persist_batch(buffer)
                except Exception:
                    logger.exception("Failed to persist alert batch")
                buffer.clear()
                last_flush = now

        if buffer:
            try:
                self._persist_batch(buffer)
            except Exception:
                logger.exception("Failed to persist alert batch")

    def stop(self):
        """请求停止后台线程。"""
        self._stop_event.set()
        try:
            self._worker_thread.join(timeout=1.0)
        except Exception:
            pass


def get_alerter(broadcast_callable: Optional[Callable[[Dict[str, Any]], Any]] = None, loop=None) -> Alerter:
    global _ALERTER
    if _ALERTER is None:
        _ALERTER = Alerter(broadcast_callable=broadcast_callable, loop=loop)
    else:
        # 更新现有实例的配置
        if broadcast_callable is not None:
            _ALERTER.set_broadcast_callable(broadcast_callable)
        if loop is not None:
            _ALERTER.set_loop(loop)
    return _ALERTER


__all__ = ["get_alerter", "Alerter"]
