from app.adapters import nmap


def test_parse_validates_and_keeps_only_open_ports(nmap_xml):
    records = nmap.parse(nmap_xml)
    assert [(r.port, r.state) for r in records] == [(3000, "open"), (8080, "closed")]

    drafts = nmap.to_drafts(records)
    assert len(drafts) == 1
    draft = drafts[0]
    assert draft.canonical_key == "nmap:127.0.0.1:tcp/3000"
    assert draft.severity.value == "info"
    assert draft.evidence[0].excerpt == "tcp/3000 open ppp"


def test_unknown_state_fails_validation(nmap_xml):
    bad = nmap_xml.replace('state="open"', 'state="weird"')
    try:
        nmap.parse(bad)
    except ValueError as exc:
        assert "weird" in str(exc)
    else:
        raise AssertionError("invalid nmap state was accepted")
