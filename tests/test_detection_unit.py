import time

from app.services.detection import DetectionContext, ContextManager


def test_detection_context_append_truncates_to_max_buffer():
    ctx = DetectionContext("f", "TCP", "a", "b", max_buffer=5)
    ctx.append(b"1234")
    ctx.append(b"5678")
    assert ctx.get_buffer() == b"45678"[-5:]


def test_context_manager_get_or_create_is_stable():
    mgr = ContextManager(timeout=1.0)
    a = mgr.get_or_create("TCP", "1.1.1.1", "2.2.2.2", 1, 2)
    b = mgr.get_or_create("TCP", "1.1.1.1", "2.2.2.2", 1, 2)
    assert a is b


def test_context_manager_evict_expired_removes_old():
    mgr = ContextManager(timeout=0.01)
    ctx = mgr.get_or_create("TCP", "1.1.1.1", "2.2.2.2", 1, 2)
    ctx.last_seen = time.time() - 999
    mgr.evict_expired()
    assert mgr.get_context(ctx.flow_id) is None


def test_context_manager_force_count_evicts_oldest_first():
    mgr = ContextManager(timeout=9999, max_contexts=10)
    c1 = mgr.get_or_create("TCP", "1", "2", 1, 2)
    c2 = mgr.get_or_create("TCP", "1", "2", 3, 4)
    c3 = mgr.get_or_create("TCP", "1", "2", 5, 6)

    # Set last_seen so that c1 is oldest
    now = time.time()
    c1.last_seen = now - 3.0
    c2.last_seen = now - 2.0
    c3.last_seen = now - 1.0

    mgr.evict_expired(force_count=1)
    assert mgr.get_context(c1.flow_id) is None
    assert mgr.get_context(c2.flow_id) is not None
    assert mgr.get_context(c3.flow_id) is not None
