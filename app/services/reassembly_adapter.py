# -*- coding: utf-8 -*-
"""TCP reassembly utilities.

为上层（HTTP 解析/规则匹配）提供“尽可能连续”的 TCP 字节流片段。

"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

logger = logging.getLogger("ids.reasm_adapter")


@dataclass
class _FlowState:
    buf: "SimpleReassemblyBuffer"
    last_seen: float


class FlowReassemblerManager:
    """Per-flow TCP reassembly manager."""

    def __init__(
        self,
        max_buffer: int = 1024 * 1024,
        flow_timeout: int = 120,
        max_flows: int = 10000,
    ):
        self.max_buffer = max_buffer
        self.flow_timeout = flow_timeout
        self.max_flows = max_flows
        # fid -> _FlowState
        self._flows: Dict[str, _FlowState] = {}

        logger.info(
            "Using local TCP reassembly (best-effort). max_buffer=%d flow_timeout=%ds max_flows=%d",
            max_buffer,
            flow_timeout,
            max_flows,
        )

    def _flow_id(self, proto: str, src: str, dst: str, sport: Optional[int], dport: Optional[int]) -> str:
        return f"{proto}:{src}:{sport}->{dst}:{dport}"

    def _cleanup_expired(self, now: float) -> None:
        # 删除超时 flow
        if not self._flows:
            return
        expired = [fid for fid, st in self._flows.items() if now - st.last_seen > self.flow_timeout]
        for fid in expired:
            try:
                del self._flows[fid]
            except Exception:
                pass

        # 如果 flow 数过多，删除最久未使用的
        if len(self._flows) > self.max_flows:
            try:
                # sort by last_seen asc
                victims = sorted(self._flows.items(), key=lambda kv: kv[1].last_seen)[: max(1, len(self._flows) - self.max_flows)]
                for fid, _ in victims:
                    del self._flows[fid]
            except Exception:
                pass

    def append(
        self,
        proto: str,
        src: str,
        dst: str,
        seq: int,
        data: bytes,
        sport: Optional[int] = None,
        dport: Optional[int] = None,
    ) -> bytes:
        """Append a TCP segment to the flow buffer.

        Returns contiguous bytes starting from the flow's next_expected_seq (may be empty).
        """
        if not data:
            return b""

        fid = self._flow_id(proto, src, dst, sport, dport)
        now = time.time()

        # opportunistic cleanup
        try:
            self._cleanup_expired(now)
        except Exception:
            pass

        st = self._flows.get(fid)
        if st is None:
            st = _FlowState(buf=SimpleReassemblyBuffer(max_buffer=self.max_buffer), last_seen=now)
            self._flows[fid] = st
        else:
            st.last_seen = now

        try:
            return st.buf.add_segment(seq, data)
        except Exception:
            logger.exception("Local reassembly failed for flow %s", fid)
            # reset this flow on unexpected error to avoid poisoning future parsing
            try:
                del self._flows[fid]
            except Exception:
                pass
            return b""


class SimpleReassemblyBuffer:
    """Best-effort TCP reassembly buffer.

    Key points:
    - Maintain next_expected_seq.
    - Cache out-of-order segments in a dict: seq -> bytes.
    - Handle retransmissions by keeping the longest payload for the same seq.
    - Only emit contiguous bytes starting from next_expected_seq.
    """

    def __init__(self, max_buffer: int = 1024 * 1024, max_out_of_order: int = 256):
        self.max_buffer = max_buffer
        self.max_out_of_order = max_out_of_order

        self.segments: Dict[int, bytes] = {}
        self.total_buffered = 0
        self.next_expected_seq: Optional[int] = None

    def add_segment(self, seq: int, data: bytes) -> bytes:
        if not data:
            return b""

        if self.next_expected_seq is None:
            # 初始化基准 seq：以首次看到的 seq 作为起点
            self.next_expected_seq = seq

        # 如果段完全在已输出范围之前，忽略（旧重传）
        if self.next_expected_seq is not None and seq + len(data) <= self.next_expected_seq:
            return b""

        # 如果段与 next_expected_seq 有部分重叠，裁掉已经输出过的部分
        if self.next_expected_seq is not None and seq < self.next_expected_seq:
            cut = self.next_expected_seq - seq
            if cut < len(data):
                data = data[cut:]
                seq = self.next_expected_seq
            else:
                return b""

        # 重传处理：同 seq 取更长的数据覆盖
        old = self.segments.get(seq)
        if old is None:
            self.segments[seq] = data
            self.total_buffered += len(data)
        else:
            if len(data) > len(old):
                self.segments[seq] = data
                self.total_buffered += (len(data) - len(old))
            else:
                # keep existing
                pass

        # 控制乱序段数量，避免被打爆
        if len(self.segments) > self.max_out_of_order:
            self._evict_far_segments()

        # 控制总 buffer
        if self.total_buffered > self.max_buffer:
            self._evict_far_segments(force=True)

        return self._emit_contiguous()

    def _emit_contiguous(self) -> bytes:
        if self.next_expected_seq is None:
            return b""

        out = bytearray()
        while True:
            seg = self.segments.get(self.next_expected_seq)
            if seg is None:
                break
            # consume this segment
            del self.segments[self.next_expected_seq]
            self.total_buffered -= len(seg)
            out.extend(seg)
            self.next_expected_seq += len(seg)

            if len(out) >= self.max_buffer:
                break

        return bytes(out)

    def _evict_far_segments(self, force: bool = False) -> None:
        """Evict segments that are far away from next_expected_seq.

        Strategy:
        - Prefer evicting segments with the largest seq (farthest in the future).
        - If force and still over limit, reset buffer.
        """
        if self.next_expected_seq is None or not self.segments:
            return

        try:
            # sort by seq desc, remove until under thresholds
            for s in sorted(self.segments.keys(), reverse=True):
                if len(self.segments) <= self.max_out_of_order and self.total_buffered <= self.max_buffer:
                    break
                b = self.segments.pop(s, None)
                if b is not None:
                    self.total_buffered -= len(b)
        except Exception:
            # on any unexpected condition, reset
            self.segments.clear()
            self.total_buffered = 0

        if force and (self.total_buffered > self.max_buffer):
            # hard reset
            self.segments.clear()
            self.total_buffered = 0


__all__ = ["FlowReassemblerManager"]
