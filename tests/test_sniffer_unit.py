import queue

import app.metrics as metrics
from app.services.sniffer import SnifferManager


class _C:
    def __init__(self):
        self.value = 0

    def inc(self, n=1):
        self.value += n


class _G:
    def __init__(self):
        self.value = None

    def set(self, v):
        self.value = v


class _H:
    def __init__(self):
        self.values = []

    def observe(self, v):
        self.values.append(v)


async def _dummy_broadcast(_msg):
    return None


def test_enqueue_packet_increments_metrics(monkeypatch):
    enq = _C()
    drop = _C()
    depth = _G()
    monkeypatch.setattr(metrics, "SNIFFER_ENQUEUED", enq)
    monkeypatch.setattr(metrics, "SNIFFER_DROPPED", drop)
    monkeypatch.setattr(metrics, "SNIFFER_QUEUE_DEPTH", depth)

    m = SnifferManager()
    m._queue = queue.Queue(maxsize=10)

    m.enqueue_packet(object(), _dummy_broadcast)
    assert enq.value == 1
    assert drop.value == 0
    assert depth.value == 1


def test_enqueue_packet_queue_full_drops(monkeypatch):
    enq = _C()
    drop = _C()
    depth = _G()
    monkeypatch.setattr(metrics, "SNIFFER_ENQUEUED", enq)
    monkeypatch.setattr(metrics, "SNIFFER_DROPPED", drop)
    monkeypatch.setattr(metrics, "SNIFFER_QUEUE_DEPTH", depth)

    m = SnifferManager()
    m._queue = queue.Queue(maxsize=1)
    m._queue.put_nowait(object())

    m.enqueue_packet(object(), _dummy_broadcast)
    assert enq.value == 0
    assert drop.value == 1


def test_worker_loop_processes_one_packet_and_observes_time(monkeypatch):
    depth = _G()
    hist = _H()
    monkeypatch.setattr(metrics, "SNIFFER_QUEUE_DEPTH", depth)
    monkeypatch.setattr(metrics, "PACKET_PROCESSING_SECONDS", hist)

    m = SnifferManager()
    m._queue = queue.Queue(maxsize=10)
    m._queue.put_nowait({"pkt": 1})

    processed = {"ok": False}

    def _fake_process_packet(pkt, bc):
        assert bc is _dummy_broadcast
        processed["ok"] = True
        m._worker_stop.set()

    monkeypatch.setattr(m, "process_packet", _fake_process_packet)
    m._broadcast_callable = _dummy_broadcast

    m._worker_stop.clear()
    m._stop_event.clear()
    m._worker_loop()

    assert processed["ok"] is True
    assert len(hist.values) >= 1
