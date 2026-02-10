from app.services import snort_importer as si


def test_parse_content_options_attaches_following_modifiers():
    p = si.SnortRuleParser()
    opts = 'content:"foo"; offset:5; depth:3; nocase; content:"bar"; within:4; distance:1;'
    items = p._parse_content_options(opts)
    assert len(items) == 2
    assert items[0].content == "foo"
    assert items[0].modifiers["offset"] == 5
    assert items[0].modifiers["depth"] == 3
    assert items[0].modifiers["nocase"] is True
    assert items[1].content == "bar"
    assert items[1].modifiers["within"] == 4
    assert items[1].modifiers["distance"] == 1


def test_parse_content_options_inline_modifiers():
    p = si.SnortRuleParser()
    opts = 'content:"foo",offset 7,depth 9;'
    items = p._parse_content_options(opts)
    assert len(items) == 1
    assert items[0].modifiers["offset"] == 7
    assert items[0].modifiers["depth"] == 9


def test_parse_rule_collects_content_items():
    p = si.SnortRuleParser()
    rule = 'alert tcp any any -> any 80 (msg:"x"; content:"foo"; nocase; sid:1; rev:1;)'
    r = p.parse_rule(rule)
    assert r is not None
    assert "content" in r.options
    assert len(r.options["content"]) == 1
    assert r.options["content"][0].content == "foo"
    assert r.options["content"][0].modifiers.get("nocase") is True


def test_convert_to_system_rule_includes_content_patterns_and_options(monkeypatch):
    # Avoid DB access in get_snort_variables.
    monkeypatch.setattr(si, "get_snort_variables", lambda: si.DEFAULT_SNORT_VARIABLES)

    parser = si.SnortRuleParser()
    snort_rule = si.SnortRule(
        action="alert",
        protocol="tcp",
        src_ip="any",
        src_port="any",
        direction="->",
        dst_ip="any",
        dst_port="80",
        options={
            "sid": "100",
            "rev": "1",
            "msg": "t",
            "content": [
                si.ContentItem(content="foo", modifiers={"offset": 1, "depth": 3, "nocase": True}),
                si.ContentItem(content="bar", modifiers={"distance": 2, "within": 10}),
            ],
        },
        raw_rule="",
    )

    out = parser.convert_to_system_rule(snort_rule)
    md = out.get("metadata") or {}
    assert md.get("content_patterns") == ["foo", "bar"]
    opts = md.get("content_options")
    assert isinstance(opts, list)
    assert opts[0]["offset"] == 1
    assert opts[0]["depth"] == 3
    assert opts[0]["nocase"] is True
    assert opts[1]["distance"] == 2
    assert opts[1]["within"] == 10
