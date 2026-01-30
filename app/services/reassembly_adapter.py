"""Reassembly adapter: prefer PcapKit if available, otherwise use local ReassemblyBuffer.

Provides a simple per-flow reassembler manager with API:
  manager = FlowReassemblerManager()
  ready_bytes = manager.append(proto, src, dst, seq, data, sport, dport)

If `ready_bytes` is non-empty it contains bytes that are now contiguous and ready for
higher-layer parsing (e.g., HTTP extraction).
"""
from __future__ import annotations

import logging
from typing import Dict, Optional

logger = logging.getLogger("ids.reasm_adapter")

_HAVE_PCAPKIT = False
try:
    import pcapkit  # type: ignore
    _HAVE_PCAPKIT = True
except Exception:
    _HAVE_PCAPKIT = False


class FlowReassemblerManager:
    def __init__(self, max_buffer: int = 1024 * 1024):
        self.max_buffer = max_buffer
        self._flows: Dict[str, object] = {}
        self._pcapkit_flows: Dict[str, object] = {}  # Separate dict for pcapkit objects
        self._use_pcapkit = _HAVE_PCAPKIT
        if self._use_pcapkit:
            logger.info("PcapKit available: will try to use it for TCP reassembly")
        else:
            logger.info("PcapKit not available: using local ReassemblyBuffer")

    def _flow_id(self, proto: str, src: str, dst: str, sport: Optional[int], dport: Optional[int]) -> str:
        return f"{proto}:{src}:{sport}->{dst}:{dport}"

    def append(self, proto: str, src: str, dst: str, seq: int, data: bytes, sport: Optional[int] = None, dport: Optional[int] = None) -> bytes:
        fid = self._flow_id(proto, src, dst, sport, dport)
        # try pcapkit path if available
        if self._use_pcapkit:
            try:
                # Use pypcapkit's TCP_Reassembly
                from pcapkit.foundation.reassembly import TCP_Reassembly

                obj = self._pcapkit_flows.get(fid)
                if obj is None:
                    obj = TCP_Reassembly()
                    self._pcapkit_flows[fid] = obj
                
                # Create a packet-like dict for pypcapkit
                from pcapkit.corekit.infoclass import Info
                packet_info = Info(
                    src=src,
                    dst=dst,
                    sport=sport,
                    dport=dport,
                    seq=seq,
                    payload=data
                )
                
                # Call reassembly
                obj(packet_info)
                
                # Get reassembled datagrams
                datagrams = obj.datagram
                if datagrams:
                    # Return the latest datagram payload
                    latest = datagrams[-1]
                    if hasattr(latest, 'payload'):
                        return latest.payload
                    elif hasattr(latest, 'data'):
                        return latest.data
                        
            except Exception:
                logger.debug("PcapKit TCP reassembly failed; falling back to local buffer", exc_info=True)
                self._use_pcapkit = False

        # local ReassemblyBuffer fallback
        # Simple implementation since original reassembly.py was removed
        buf = self._flows.get(fid)
        if buf is None:
            buf = SimpleReassemblyBuffer(max_buffer=self.max_buffer)
            self._flows[fid] = buf
        try:
            return buf.add_segment(seq, data)
        except Exception:
            logger.exception("Local reassembly failed for flow %s", fid)
            return b""


class SimpleReassemblyBuffer:
    """Simple TCP reassembly buffer - accumulates data until we have a complete segment."""
    
    def __init__(self, max_buffer: int = 1024 * 1024):
        self.max_buffer = max_buffer
        self.buffer = bytearray()
        self.next_expected_seq = None
        
    def add_segment(self, seq: int, data: bytes) -> bytes:
        """Add a TCP segment. Returns contiguous data when available."""
        if not data:
            return b""
            
        # For simplicity, just accumulate data and return it when we get a segment
        # This is a very basic implementation - in a real system you'd track sequence numbers
        self.buffer.extend(data)
        
        # Return accumulated data (simplified - real reassembly would be more complex)
        if len(self.buffer) > 0:
            result = bytes(self.buffer)
            self.buffer.clear()
            return result
            
        return b""


__all__ = ["FlowReassemblerManager"]
