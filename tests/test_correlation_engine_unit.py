import app.services.correlation_engine as ce


def test_marks_suspected_attacker_when_thresholds_met(monkeypatch):
    t = {"now": 1000.0}

    monkeypatch.setattr(ce.time, "time", lambda: t["now"])

    eng = ce.CorrelationEngine(window_size=60, min_rule_diversity=2, min_alerts=3, behavior_alert_weight=2)
    eng.add_alert("1.1.1.1", "r1", is_behavior=False)
    eng.add_alert("1.1.1.1", "r2", is_behavior=False)
    # behavior alert counts as 2
    eng.add_alert("1.1.1.1", "port_scan", is_behavior=True)

    ok, sev = eng.is_suspected_attacker("1.1.1.1")
    assert ok is True
    assert sev in ("medium", "high")


def test_get_suspected_attackers_cleans_expired(monkeypatch):
    t = {"now": 1000.0}
    monkeypatch.setattr(ce.time, "time", lambda: t["now"])

    eng = ce.CorrelationEngine(window_size=10, min_rule_diversity=1, min_alerts=1, behavior_alert_weight=1)
    eng.add_alert("1.1.1.1", "r1", is_behavior=False)
    assert eng.get_suspected_attackers()

    # advance > 2*window
    t["now"] += 25
    attackers = eng.get_suspected_attackers()
    assert "1.1.1.1" not in attackers


def test_db_persist_failure_is_swallowed(monkeypatch):
    t = {"now": 1000.0}
    monkeypatch.setattr(ce.time, "time", lambda: t["now"])

    # Force SessionLocal to raise when imported/used.
    import app.db as db

    monkeypatch.setattr(db, "SessionLocal", lambda: (_ for _ in ()).throw(RuntimeError("db down")))

    eng = ce.CorrelationEngine(window_size=60, min_rule_diversity=1, min_alerts=1, behavior_alert_weight=1)
    eng.add_alert("2.2.2.2", "r1", is_behavior=False)
    ok, _ = eng.is_suspected_attacker("2.2.2.2")
    assert ok is True
