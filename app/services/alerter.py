import threading
import time
from typing import Callable, Optional, Dict, Any, Tuple
import logging

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

    def __init__(self, broadcast_callable: Optional[Callable[[Dict[str, Any]], Any]] = None, loop=None, dedupe_window: int = 60, flush_interval: int = 5):
        self.broadcast_callable = broadcast_callable
        self.loop = loop
        self.dedupe_window = dedupe_window
        self.flush_interval = flush_interval

        # ensure ALERTS_EMITTED imported
        try:
            from app.metrics import ALERTS_EMITTED
        except Exception:
            pass

        self._lock = threading.Lock()
        # Aggregation buckets removed: we persist and broadcast every occurrence.
        # No background flusher thread is started.
        # recent alert fingerprints to suppress immediate duplicates (very short TTL)
        self._recent_alerts: Dict[str, float] = {}

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
        # replace non-printable/control chars with space
        s = ''.join(ch if (32 <= ord(ch) <= 126 or ord(ch) >= 160) else ' ' for ch in s)
        # collapse multiple spaces
        s = ' '.join(s.split())
        if len(s) > maxlen:
            s = s[:maxlen] + '…'
        return s

    def handle_alert(self, alert: Dict[str, Any]):
        # Persist and broadcast every occurrence, but suppress nearly-simultaneous exact duplicates.
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
                    if now - t > 1.0:
                        del self._recent_alerts[k]
            except Exception:
                pass

            if fp is not None and fp in self._recent_alerts:
                return

            if fp is not None:
                self._recent_alerts[fp] = now

            try:
                self._persist(alert)
            except Exception:
                logger.exception("Failed to persist alert")
            try:
                self._broadcast(alert)
            except Exception:
                logger.exception("Failed to broadcast alert")
            try:
                ALERTS_EMITTED.inc()
            except Exception:
                logger.exception("Failed to increment ALERTS_EMITTED")

    def _persist(self, alert: Dict[str, Any]):
        try:
            session = SessionLocal()
            # Persist only the match_text and a short preview (通常为 URL 或 packet_summary)，并对文本做脱敏/截断
            mt = self._sanitize_text(alert.get("match_text"), maxlen=400)
            pv = alert.get("payload_preview") if alert.get("payload_preview") is not None else alert.get("packet_summary")
            pv = self._sanitize_text(pv, maxlen=400)
            am = AlertModel(
                rule_id=alert.get("match_rule"),
                match_text=mt,
                src_ip=alert.get("src_ip"),
                dst_ip=alert.get("dst_ip"),
                pos_start=alert.get("pos_start"),
                pos_end=alert.get("pos_end"),
                payload_preview=pv,
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
            for k in ("packet_summary", "match_text", "payload_preview", "timestamp"):
                if k in safe:
                    try:
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

    # Aggregation/flusher removed: alerts are recorded and broadcast immediately on receipt.

    def stop(self):
        # nothing to stop (no flusher thread)
        return


def get_alerter(broadcast_callable: Optional[Callable[[Dict[str, Any]], Any]] = None, loop=None) -> Alerter:
    global _ALERTER
    if _ALERTER is None:
        _ALERTER = Alerter(broadcast_callable=broadcast_callable, loop=loop)
    return _ALERTER


__all__ = ["get_alerter", "Alerter"]
