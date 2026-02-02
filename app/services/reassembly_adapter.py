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

_HAVE_PCAPKIT = False  # Disable pcapkit due to parsing errors


class FlowReassemblerManager:
    def __init__(self, max_buffer: int = 1024 * 1024):
        self.max_buffer = max_buffer
        self._flows: Dict[str, object] = {}
        self._pcapkit_flows: Dict[str, object] = {}  # Separate dict for pcapkit objects
        self._failed_flows: set = set()  # Track flows that failed with PcapKit
        self._use_pcapkit = _HAVE_PCAPKIT
        if self._use_pcapkit:
            logger.info("PcapKit available: will try to use it for TCP reassembly")
        else:
            logger.info("PcapKit not available: using local ReassemblyBuffer")

    def _flow_id(self, proto: str, src: str, dst: str, sport: Optional[int], dport: Optional[int]) -> str:
        return f"{proto}:{src}:{sport}->{dst}:{dport}"

    def append(self, proto: str, src: str, dst: str, seq: int, data: bytes, sport: Optional[int] = None, dport: Optional[int] = None) -> bytes:
        fid = self._flow_id(proto, src, dst, sport, dport)
        
        # Check if this flow has failed with PcapKit before
        if fid in self._failed_flows:
            # Use local implementation for this flow
            return self._append_local(fid, seq, data)
        
        # try pcapkit path if available
        if self._use_pcapkit:
            try:
                # Use pypcapkit's TCP_Reassembly
                from pcapkit.foundation.reassembly import TCP_Reassembly
                from pcapkit.foundation.reassembly.data.tcp import Packet

                obj = self._pcapkit_flows.get(fid)
                if obj is None:
                    obj = TCP_Reassembly()
                    self._pcapkit_flows[fid] = obj
                
                # Create Packet object with correct parameters for PcapKit
                packet_info = Packet(
                    bufid=(src, sport, dst, dport),  # Buffer identifier as tuple
                    dsn=seq,          # Data Sequence Number
                    ack=0,            # Acknowledgement Number (default)
                    num=1,            # Packet number (default)
                    syn=False,        # Synchronise Flag
                    fin=False,        # Finish Flag
                    rst=False,        # Reset Flag
                    len=len(data),    # Packet length
                    first=seq,        # First sequence number
                    last=seq + len(data),  # Last sequence number
                    header=b'',       # TCP header (empty for now)
                    payload=bytearray(data)  # Convert to mutable bytearray
                )
                
                # Call reassembly
                obj.reassembly(packet_info)
                
                # Get reassembled datagrams
                datagrams = obj.datagram
                if datagrams:
                    # Return the latest datagram payload
                    latest = datagrams[-1]
                    if hasattr(latest, 'payload'):
                        return latest.payload
                    elif hasattr(latest, 'packet') and hasattr(latest.packet, 'raw'):
                        return latest.packet.raw
                        
            except Exception as e:
                logger.debug("PcapKit library failed to process TCP packet for flow %s (seq=%d, len=%d): %s", 
                           fid, seq, len(data), str(e))
                logger.warning("PcapKit TCP reassembly failed for flow %s: %s. Using local buffer for this flow.", fid, e)
                self._failed_flows.add(fid)  # Mark this flow as failed
                # Fall through to local implementation
        
        # Local ReassemblyBuffer fallback
        return self._append_local(fid, seq, data)
    
    def _append_local(self, fid: str, seq: int, data: bytes) -> bytes:
        """Local TCP reassembly implementation."""
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
    """Simple TCP reassembly buffer - accumulates contiguous data segments."""
    
    def __init__(self, max_buffer: int = 1024 * 1024):
        self.max_buffer = max_buffer
        self.segments = {}  # seq -> data
        self.next_expected_seq = None
        self.total_buffered = 0
        
    def add_segment(self, seq: int, data: bytes) -> bytes:
        """Add a TCP segment. Returns contiguous data when a complete segment is available."""
        if not data:
            return b""
            
        # Store the segment
        if seq not in self.segments:
            self.segments[seq] = data
            self.total_buffered += len(data)
            
            # Check if we exceed buffer limit
            if self.total_buffered > self.max_buffer:
                # Clear old segments to free memory
                oldest_seq = min(self.segments.keys())
                removed_data = self.segments.pop(oldest_seq)
                self.total_buffered -= len(removed_data)
        
        # Try to assemble contiguous data
        return self._try_assemble_contiguous()
        
    def _try_assemble_contiguous(self) -> bytes:
        """Try to assemble contiguous segments starting from the lowest sequence number."""
        if not self.segments:
            return b""
            
        # Find the lowest sequence number
        min_seq = min(self.segments.keys())
        result = bytearray()
        current_seq = min_seq
        
        # Try to assemble contiguous blocks
        while current_seq in self.segments:
            segment_data = self.segments[current_seq]
            result.extend(segment_data)
            
            # Remove the processed segment
            del self.segments[current_seq]
            self.total_buffered -= len(segment_data)
            
            # Move to next expected sequence
            current_seq += len(segment_data)
            
            # Safety check to prevent infinite loops
            if len(result) > self.max_buffer:
                break
                
        # Return assembled data if we got any
        if result:
            return bytes(result)
            
        return b""


__all__ = ["FlowReassemblerManager"]
