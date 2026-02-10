from app.services.behavior_analyzer import BehaviorAnalyzer, AuthenticationTracker


def test_analyze_auth_event_triggers_bruteforce_and_calls_callback_once():
    analyzer = BehaviorAnalyzer()
    analyzer.auth_tracker = AuthenticationTracker(max_failures=2, window_size=9999)

    called = []

    def cb(alert):
        called.append(alert)

    analyzer.add_alert_callback(cb)

    a1 = analyzer.analyze_auth_event("1.1.1.1", "2.2.2.2", success=False, auth_type="ssh")
    assert a1 is None

    a2 = analyzer.analyze_auth_event("1.1.1.1", "2.2.2.2", success=False, auth_type="ssh")
    assert a2 is not None
    assert a2.alert_type == "brute_force"
    assert len(called) == 1

    # Third failure produces an alert object, but callback should be suppressed by correlation window
    a3 = analyzer.analyze_auth_event("1.1.1.1", "2.2.2.2", success=False, auth_type="ssh")
    assert a3 is not None
    assert len(called) == 1


def test_process_event_unknown_type_returns_empty():
    analyzer = BehaviorAnalyzer()
    assert analyzer.process_event({"type": "unknown"}) == []


def test_disabled_analyzer_returns_no_alerts():
    analyzer = BehaviorAnalyzer()
    analyzer.set_enabled(False)
    assert analyzer.analyze_auth_event("1", "2", success=False, auth_type="ssh") is None
    assert analyzer.analyze_packet({"src_ip": "1", "dst_ip": "2", "protocol": "tcp", "payload": b"x"}) == []
