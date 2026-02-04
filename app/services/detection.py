# -*- coding: utf-8 -*-
"""检测上下文与缓冲区管理器

提供：
- `DetectionContext`：表示单个流/会话的缓冲区（payload 累积、元数据、时间戳）
- `ContextManager`：管理多个 `DetectionContext` 的创建、获取、过期清理与并发保护

设计目标：
- 将包/流信息组织成可供规则引擎检索的上下文，而不是在包回调内直接做复杂判断
- 提供超时/窗口控制，避免无限增长内存
"""
from __future__ import annotations

import threading
import time
from typing import Dict, Optional


class DetectionContext:
    """单个检测上下文，按流（五元组）聚合数据。

    属性：
    - flow_id: 唯一流标识（由 five-tuple 生成）
    - proto, src, dst, sport, dport: 基本元数据
    - buffer: bytes 累积的 payload（可按需限制长度）
    - first_seen, last_seen: 时间戳
    """

    def __init__(self, flow_id: str, proto: str, src: str, dst: str, sport: Optional[int] = None, dport: Optional[int] = None, max_buffer: int = 65536):
        self.flow_id = flow_id
        self.proto = proto
        self.src = src
        self.dst = dst
        self.sport = sport
        self.dport = dport

        self.buffer = bytearray()
        self.max_buffer = max_buffer

        now = time.time()
        self.first_seen = now
        self.last_seen = now

        # 用于外部标记，例如已触发哪些 rule id 等
        self.meta = {}

    def append(self, payload: bytes, ts: Optional[float] = None):
        """将 payload 追加到缓冲区（如果超过 `max_buffer`，则保留尾部）。"""
        if not payload:
            return
        if ts is None:
            ts = time.time()
        self.last_seen = ts
        self.buffer += payload
        # 限制缓冲区大小，保留末尾内容
        if len(self.buffer) > self.max_buffer:
            excess = len(self.buffer) - self.max_buffer
            del self.buffer[:excess]

    def get_buffer(self) -> bytes:
        return bytes(self.buffer)

    def clear(self):
        self.buffer.clear()

    def age(self) -> float:
        return time.time() - self.last_seen


class ContextManager:
    """管理多个 DetectionContext 的生命周期。

    - 使用线程锁保护，适合在嗅探线程与规则/引擎线程之间共享
    - 提供获取/创建上下文、清理过期上下文、以及列出当前上下文
    """

    def __init__(self, timeout: float = 120.0, max_contexts: int = 10000):
        self._contexts: Dict[str, DetectionContext] = {}
        self._lock = threading.RLock()
        self.timeout = timeout
        self.max_contexts = max_contexts

    def _make_flow_id(self, proto: str, src: str, dst: str, sport: Optional[int], dport: Optional[int]) -> str:
        return f"{proto}:{src}:{sport}->{dst}:{dport}"

    def get_or_create(self, proto: str, src: str, dst: str, sport: Optional[int] = None, dport: Optional[int] = None) -> DetectionContext:
        flow_id = self._make_flow_id(proto, src, dst, sport, dport)
        with self._lock:
            ctx = self._contexts.get(flow_id)
            if ctx is None:
                # 若超过容量，先触发清理
                if len(self._contexts) >= self.max_contexts:
                    self.evict_expired(force_count= max(1, int(self.max_contexts * 0.1)))
                ctx = DetectionContext(flow_id, proto, src, dst, sport, dport)
                self._contexts[flow_id] = ctx
            return ctx

    def append_to_flow(self, proto: str, src: str, dst: str, payload: bytes, sport: Optional[int] = None, dport: Optional[int] = None, ts: Optional[float] = None) -> DetectionContext:
        ctx = self.get_or_create(proto, src, dst, sport, dport)
        ctx.append(payload, ts=ts)
        return ctx

    def evict_expired(self, force_count: int = 0):
        """移除超过 timeout 的上下文；若 force_count>0，优先移除最老的 N 个。"""
        now = time.time()
        with self._lock:
            # 找到所有过期的
            expired = [fid for fid, c in self._contexts.items() if (now - c.last_seen) > self.timeout]
            for fid in expired:
                del self._contexts[fid]
            # 若还需要强制裁剪，按 last_seen 升序删除
            if force_count > 0 and len(self._contexts) > 0:
                items = sorted(self._contexts.items(), key=lambda kv: kv[1].last_seen)
                to_remove = min(force_count, len(items))
                for i in range(to_remove):
                    fid = items[i][0]
                    del self._contexts[fid]

    def get_context(self, flow_id: str) -> Optional[DetectionContext]:
        with self._lock:
            return self._contexts.get(flow_id)

    def list_contexts(self):
        with self._lock:
            return list(self._contexts.values())


__all__ = ["DetectionContext", "ContextManager"]
