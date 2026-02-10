import importlib


def test_monitor_generates_alert_and_respects_cooldown(monkeypatch):
    # Patch alerter Thread to avoid background worker threads during import.
    import app.services.alerter as al

    class _DummyThread:
        def __init__(self, *args, **kwargs):
            pass

        def start(self):
            return None

        def join(self, timeout=None):
            return None

    monkeypatch.setattr(al.threading, "Thread", _DummyThread)

    # Reload correlation_monitor so its global singleton uses patched Thread.
    import app.services.correlation_monitor as cm

    importlib.reload(cm)

    # Create a fresh monitor instance to test.
    mon = cm.CorrelationMonitor(interval=1)

    calls = []

    class _DummyAlerter:
        def handle_alert(self, alert):
            calls.append(alert)

    class _DummyEngine:
        def __init__(self):
            self._attackers = {"1.1.1.1": (1000.0, "high")}

        def get_suspected_attackers(self):
            return dict(self._attackers)

    mon._alerter = _DummyAlerter()
    mon._engine = _DummyEngine()

    now = {"t": 2000.0}
    monkeypatch.setattr(cm.time, "time", lambda: now["t"])

    # First check emits.
    mon._check_suspected_attackers()
    assert len(calls) == 1

    # Second check within cooldown does not emit.
    mon._check_suspected_attackers()
    assert len(calls) == 1

    # After cooldown, emits again.
    now["t"] += mon._cooldown + 1
    mon._check_suspected_attackers()
    assert len(calls) == 2
