from bgpwatch.model import events_from_ris


def test_normalise_live_format():
    # field layout as received from RIS Live on 2026-11-14 (host is an FQDN, origin upper-case)
    d = {"timestamp": 1794589038.44, "peer": "37.49.236.249", "peer_asn": "49434", "id": "x", "host": "rrc21.ripe.net",
         "type": "UPDATE", "path": [49434, 33891, 4818], "origin": "IGP",
         "announcements": [{"next_hop": "37.49.236.249", "prefixes": ["182.62.128.0/17", "182.63.0.0/16"]}],
         "withdrawals": ["10.0.0.0/8"]}
    evs = events_from_ris(d)
    assert [(e.kind, e.prefix) for e in evs] == [("W", "10.0.0.0/8"), ("A", "182.62.128.0/17"), ("A", "182.63.0.0/16")]
    a = evs[1]
    assert a.peer == "rrc21|37.49.236.249" and a.origin == 4818 and a.path == (49434, 33891, 4818) and a.peer_asn == 49434


def test_as_set_and_non_update():
    evs = events_from_ris({"timestamp": 1, "peer": "p", "peer_asn": "1", "host": "rrc00", "type": "UPDATE",
                           "path": [1, 2, [3, 4]], "announcements": [{"next_hop": "x", "prefixes": ["1.0.0.0/24"]}]})
    assert evs[0].origin is None and evs[0].path == (1, 2, (3, 4))
    assert events_from_ris({"type": "KEEPALIVE", "timestamp": 1}) == []
