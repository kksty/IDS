import time

from app.services import engine as engine_mgr
from app.models.rule import Rule


def test_engine_rebuild_and_match():
    # create a temporary rule and add to engine (sync rebuild)
    r = Rule(rule_id="T1", pattern="secret_value", pattern_type="string")
    # add without immediate rebuild, then force rebuild synchronously
    engine_mgr.add_rule(r, rebuild=False)
    # call rebuild_async and wait briefly for background task to finish
    engine_mgr.rebuild_async()
    time.sleep(0.5)

    # payload containing the pattern should match
    res = engine_mgr.match_payload(b"this has secret_value inside")
    assert isinstance(res, list)
    assert len(res) >= 1
