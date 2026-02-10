import importlib

import pytest


class DummyThread:
    def __init__(self, target=None, args=(), kwargs=None, daemon=None, name=None):
        self._target = target
        self._args = args
        self._kwargs = kwargs or {}
        self.daemon = daemon
        self.name = name
        self.started = False

    def start(self):
        self.started = True
        if self._target:
            self._target(*self._args, **self._kwargs)

    def join(self, timeout=None):
        return None


class CapturingThread(DummyThread):
    created = []

    def start(self):
        self.started = True
        CapturingThread.created.append(self)


class DummyLoop:
    def __init__(self):
        self.calls = []

    def call_soon_threadsafe(self, fn, *args):
        self.calls.append((fn, args))
        fn(*args)


async def _dummy_broadcast(_msg):
    return None


def _import_system_manager_with_dummy_threads(monkeypatch):
    import app.services.alerter as alerter

    monkeypatch.setattr(alerter.threading, "Thread", DummyThread)

    import app.services.correlation_monitor as correlation_monitor

    importlib.reload(correlation_monitor)

    import app.services.system_manager as system_manager

    importlib.reload(system_manager)
    return system_manager


def test_analyze_pcap_missing_file_raises(monkeypatch):
    system_manager = _import_system_manager_with_dummy_threads(monkeypatch)
    monkeypatch.setattr(system_manager.os.path, "exists", lambda _p: False)

    mgr = system_manager.SystemManager()
    mgr.set_event_loop(DummyLoop())
    mgr.set_broadcast_callable(_dummy_broadcast)

    with pytest.raises(FileNotFoundError):
        mgr.analyze_pcap("/nope/file.pcap")


def test_analyze_pcap_calls_process_pcap(monkeypatch):
    system_manager = _import_system_manager_with_dummy_threads(monkeypatch)
    monkeypatch.setattr(system_manager.os.path, "exists", lambda _p: True)

    import app.services.sniffer as sniffer

    calls = {"args": None, "kwargs": None}

    def _fake_process_pcap(*args, **kwargs):
        calls["args"] = args
        calls["kwargs"] = kwargs
        return 3

    monkeypatch.setattr(sniffer, "process_pcap", _fake_process_pcap)

    mgr = system_manager.SystemManager()
    mgr.set_event_loop(DummyLoop())
    mgr.set_broadcast_callable(_dummy_broadcast)

    processed = mgr.analyze_pcap("/tmp/a.pcap")
    assert processed == 3
    assert calls["args"][0] == "/tmp/a.pcap"
    assert "manager" in calls["kwargs"]


def test_start_pcap_job_completes_and_updates_status(monkeypatch):
    system_manager = _import_system_manager_with_dummy_threads(monkeypatch)
    monkeypatch.setattr(system_manager.os.path, "exists", lambda _p: True)
    monkeypatch.setattr(system_manager.threading, "Thread", DummyThread)

    import app.services.sniffer as sniffer

    def _fake_process_pcap(path, **kwargs):
        progress_callback = kwargs.get("progress_callback")
        if progress_callback:
            progress_callback(10, 100.0, 0.1)
        return 10

    monkeypatch.setattr(sniffer, "process_pcap", _fake_process_pcap)

    mgr = system_manager.SystemManager()
    mgr.set_event_loop(DummyLoop())
    mgr.set_broadcast_callable(_dummy_broadcast)

    job_id = mgr.start_pcap_job("/tmp/a.pcap")
    job = mgr.get_pcap_job(job_id)

    assert job is not None
    assert job["status"] == "completed"
    assert job["processed"] == 10


def test_stop_pcap_job_marks_stopped(monkeypatch):
    system_manager = _import_system_manager_with_dummy_threads(monkeypatch)
    monkeypatch.setattr(system_manager.os.path, "exists", lambda _p: True)

    # Capture the created thread so we can trigger the target after stopping.
    CapturingThread.created = []
    monkeypatch.setattr(system_manager.threading, "Thread", CapturingThread)

    import app.services.sniffer as sniffer

    def _fake_process_pcap(path, **kwargs):
        stop_event = kwargs.get("stop_event")
        assert stop_event is not None
        # SystemManager should mark "stopped" if stop_event is set.
        return 1

    monkeypatch.setattr(sniffer, "process_pcap", _fake_process_pcap)

    mgr = system_manager.SystemManager()
    mgr.set_event_loop(DummyLoop())
    mgr.set_broadcast_callable(_dummy_broadcast)

    job_id = mgr.start_pcap_job("/tmp/a.pcap")
    assert mgr.stop_pcap_job(job_id) is True

    # Now run the captured thread target synchronously.
    assert CapturingThread.created
    t = CapturingThread.created[0]
    t._target(*t._args, **t._kwargs)

    job = mgr.get_pcap_job(job_id)
    assert job is not None
    assert job["status"] == "stopped"
