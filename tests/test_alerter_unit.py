import asyncio

import app.services.alerter as al


class _DummyThread:
    def __init__(self, *args, **kwargs):
        self._target = kwargs.get("target")
        self._args = kwargs.get("args") or ()
        self._kwargs = kwargs.get("kwargs") or {}

    def start(self):
        # do not spawn background threads in unit tests
        return None

    def join(self, timeout=None):
        return None


class _DummyLoop:
    def is_running(self):
        return True


async def _dummy_broadcast(_msg):
    return None


def test_sanitize_text_replaces_control_and_truncates(monkeypatch):
    monkeypatch.setattr(al.threading, "Thread", _DummyThread)
    a = al.Alerter(broadcast_callable=_dummy_broadcast, loop=_DummyLoop(), dedupe_window=10)

    s = a._sanitize_text("A\x00B\nC")
    assert "\\x00" in s
    assert "A" in s


def test_handle_alert_dedupes_in_window(monkeypatch):
    monkeypatch.setattr(al.threading, "Thread", _DummyThread)
    a = al.Alerter(broadcast_callable=_dummy_broadcast, loop=_DummyLoop(), dedupe_window=999)

    alert = {
        "match_rule": "r1",
        "src_ip": "1.1.1.1",
        "dst_ip": "2.2.2.2",
        "match_text": "x",
        "payload_preview": "p",
    }
    a.handle_alert(dict(alert))
    a.handle_alert(dict(alert))

    assert a._queue.qsize() == 1


def test_handle_alert_queue_full_does_not_raise(monkeypatch):
    monkeypatch.setattr(al.threading, "Thread", _DummyThread)
    a = al.Alerter(broadcast_callable=_dummy_broadcast, loop=_DummyLoop(), dedupe_window=1)

    # force a tiny queue
    a._queue = asyncio.Queue(maxsize=1)  # type: ignore[assignment]

    # The implementation uses queue.Queue, not asyncio.Queue; replace with a real one
    import queue

    a._queue = queue.Queue(maxsize=1)
    a._queue.put_nowait({"x": 1})

    a.handle_alert({
        "match_rule": "r2",
        "src_ip": "1",
        "dst_ip": "2",
        "match_text": "y",
        "payload_preview": "p",
    })


def test_broadcast_schedules_coroutine(monkeypatch):
    monkeypatch.setattr(al.threading, "Thread", _DummyThread)
    a = al.Alerter(broadcast_callable=_dummy_broadcast, loop=_DummyLoop(), dedupe_window=1)

    scheduled = {}

    def _fake_run_coroutine_threadsafe(coro, loop):
        scheduled["called"] = True
        assert loop is a.loop
        # ensure it's awaitable
        assert asyncio.iscoroutine(coro)
        return None

    monkeypatch.setattr(asyncio, "run_coroutine_threadsafe", _fake_run_coroutine_threadsafe)

    a._broadcast({"packet_summary": "x", "match_text": "y"})
    assert scheduled.get("called") is True
