# -*- coding: utf-8 -*-
from prometheus_client import Counter, Histogram, Gauge

# 总处理包计数
PACKETS_PROCESSED = Counter("ids_packets_processed_total", "IDS 处理的数据包总数")
# 匹配计数
MATCHES_FOUND = Counter("ids_matches_found_total", "规则引擎命中的总次数")
# 告警计数（持久化/广播）
ALERTS_EMITTED = Counter("ids_alerts_emitted_total", "已发出的告警总数（包括聚合）")
# 行为分析告警计数
BEHAVIOR_ALERTS_EMITTED = Counter("ids_behavior_alerts_emitted_total", "行为分析告警总数")
# 引擎重建时间
ENGINE_REBUILD_SECONDS = Histogram("ids_engine_rebuild_seconds", "引擎重建耗时（秒）")
# 当前引擎是否存在（0/1 gauge）
ENGINE_READY = Gauge("ids_engine_ready", "引擎是否就绪（1 表示就绪，0 表示未就绪）")

# 嗅探/处理解耦相关指标
SNIFFER_QUEUE_DEPTH = Gauge("ids_sniffer_queue_depth", "嗅探处理队列当前长度")
SNIFFER_ENQUEUED = Counter("ids_sniffer_enqueued_total", "进入处理队列的数据包总数")
SNIFFER_DROPPED = Counter("ids_sniffer_dropped_total", "因队列满等原因丢弃的数据包总数")
PACKET_PROCESSING_SECONDS = Histogram("ids_packet_processing_seconds", "单包处理耗时（秒）")

__all__ = [
    "PACKETS_PROCESSED",
    "MATCHES_FOUND",
    "ALERTS_EMITTED",
    "BEHAVIOR_ALERTS_EMITTED",
    "ENGINE_REBUILD_SECONDS",
    "ENGINE_READY",
    "SNIFFER_QUEUE_DEPTH",
    "SNIFFER_ENQUEUED",
    "SNIFFER_DROPPED",
    "PACKET_PROCESSING_SECONDS",
]
