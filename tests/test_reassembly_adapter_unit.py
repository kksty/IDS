from app.services.reassembly_adapter import FlowReassemblerManager, SimpleReassemblyBuffer


def test_simple_reassembly_emits_contiguous_in_order():
    b = SimpleReassemblyBuffer(max_buffer=1024)
    assert b.add_segment(100, b"abc") == b"abc"
    assert b.add_segment(103, b"def") == b"def"


def test_simple_reassembly_buffers_out_of_order_until_gap_filled():
    b = SimpleReassemblyBuffer(max_buffer=1024)
    assert b.add_segment(100, b"abc") == b"abc"
    # out of order
    assert b.add_segment(106, b"ghi") == b""
    # fill the gap
    assert b.add_segment(103, b"def") == b"defghi"


def test_simple_reassembly_ignores_old_retransmission():
    b = SimpleReassemblyBuffer(max_buffer=1024)
    assert b.add_segment(10, b"hello") == b"hello"
    # fully before next_expected_seq
    assert b.add_segment(10, b"he") == b""


def test_simple_reassembly_overlap_is_trimmed():
    b = SimpleReassemblyBuffer(max_buffer=1024)
    assert b.add_segment(10, b"hello") == b"hello"
    # overlaps already emitted bytes; only new tail should be emitted
    assert b.add_segment(12, b"lloworld") == b"world"


def test_simple_reassembly_same_seq_keeps_longest():
    b = SimpleReassemblyBuffer(max_buffer=1024)
    assert b.add_segment(1, b"a") == b"a"
    # next_expected_seq now 2; retransmit at 2 with longer
    assert b.add_segment(2, b"bc") == b"bc"


def test_flow_reassembler_manager_is_best_effort_not_crashing_on_cleanup():
    m = FlowReassemblerManager(max_buffer=16, max_flows=1, flow_timeout=0)
    # append will trigger cleanup; should not crash
    out = m.append("TCP", "1.1.1.1", "2.2.2.2", 1, b"abc", 1, 2)
    assert out == b"abc"
