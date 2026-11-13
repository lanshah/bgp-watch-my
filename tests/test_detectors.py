"""Detector unit tests on hand-built events against the synthetic baseline."""
from bgpwatch import synthetic as S
from bgpwatch.model import events_from_ris

from conftest import ris


def kinds(det, msg):
    out = []
    for ev in events_from_ris(msg["data"]):
        det.s.apply(ev.prefix, ev.peer, ev.kind, ev.path)
        if ev.kind == "A":
            out += det.on_announce(ev)
    return out


def test_normal_route_is_silent(syn_det):
    assert kinds(syn_det, ris(1, 0, "198.18.0.0/22", S.normal_path(0, S.A, alt=1))) == []


def test_exact_hijack_rpki_invalid_is_critical(syn_det):
    f = kinds(syn_det, ris(1, 3, "198.18.0.0/22", [S.PEERS[3]["asn"], S.CLIQUE[0], S.HIJ1]))
    assert [(x.kind, x.severity, x.actor_asn) for x in f] == [("origin_change", "critical", S.HIJ1)]
    assert f[0].evidence["rpki"]["state"] == "invalid" and f[0].evidence["expected_origins"] == [S.A]


def test_subprefix_hijack_and_own_more_specific(syn_det):
    f = kinds(syn_det, ris(1, 1, "198.18.33.0/24", [S.PEERS[1]["asn"], S.HIJ2]))
    assert [(x.kind, x.severity) for x in f] == [("more_specific_foreign", "high")]  # no ROA -> NotFound -> high
    f = kinds(syn_det, ris(2, 1, "198.18.5.0/24", S.normal_path(1, S.A)))
    assert [(x.kind, x.severity) for x in f] == [("more_specific_own", "info")]


def test_own_route_invalid_length(syn_det):
    f = kinds(syn_det, ris(1, 2, "198.18.18.0/24", S.normal_path(2, S.B)))
    assert {x.kind for x in f} == {"more_specific_own", "rpki_invalid"}
    assert [x for x in f if x.kind == "rpki_invalid"][0].evidence["rpki"]["reason"] == "invalid-length"


def test_sibling_origin_is_not_a_hijack(syn_det):
    assert kinds(syn_det, ris(1, 4, "198.18.0.0/22", S.normal_path(4, S.A2))) == []


def test_route_leak_patterns(syn_det):
    f = kinds(syn_det, ris(1, 5, "198.18.0.0/22", [S.PEERS[5]["asn"], S.CLIQUE[0], S.LEAKER, S.CLIQUE[1], S.U1, S.A]))
    assert [(x.kind, x.actor_asn, x.evidence["pattern"]) for x in f] == [("route_leak", S.LEAKER, "clique-sandwich")]
    f = kinds(syn_det, ris(2, 6, "198.18.4.0/22", [S.PEERS[6]["asn"], S.CLIQUE[0], S.U2, S.CUSTOMER, S.A]))
    assert [(x.kind, x.actor_asn) for x in f] == [("route_leak", S.CUSTOMER)]
    # The RIS peer itself being the origin's customer is NOT a leak: collector sessions get full tables.
    assert kinds(syn_det, ris(3, 7, "198.18.4.0/22", [S.CUSTOMER, S.A])) == []


def test_new_upstream(syn_det):
    f = kinds(syn_det, ris(1, 8, "203.0.113.0/24", [S.PEERS[8]["asn"], S.CLIQUE[1], S.NEWUP, S.B]))
    assert [(x.kind, x.actor_asn, x.severity) for x in f] == [("new_upstream", S.NEWUP, "medium")]


def test_sibling_as_upstream_is_not_new(syn_det):
    # found in the first live run: TM's AS23736 reached through TM's own AS4788
    assert kinds(syn_det, ris(1, 8, "198.18.0.0/22", [S.PEERS[8]["asn"], S.CLIQUE[1], S.A2, S.A])) == []


def test_prepending_is_not_a_path_anomaly(syn_det):
    path = S.normal_path(9, S.B)[:-1] + [S.B] * 6
    assert kinds(syn_det, ris(1, 9, "198.18.16.0/22", path)) == []


def test_visibility_hold_and_hysteresis(syn_det, cfg):
    p = "198.18.8.0/24"
    for i in range(30):  # 30 of 40 peers withdraw -> 25 % visible
        syn_det.s.apply(p, f"rrc{90 + i % 4}|192.0.2.{i + 1}", "W", ())
    syn_det.dirty.add(p)
    f, _, _ = syn_det.tick_visibility(1000)
    assert f == []  # below threshold, but not for long enough yet
    f, _, _ = syn_det.tick_visibility(1000 + cfg.detect["visibility_hold_s"])
    assert [(x.kind, x.severity) for x in f] == [("visibility_drop", "high")]
    for i in range(10):  # back to 50 %: inside the hysteresis band, still active
        syn_det.s.apply(p, f"rrc{90 + i % 4}|192.0.2.{i + 1}", "A", tuple(S.normal_path(i, S.A)))
    f, cleared, _ = syn_det.tick_visibility(1400)
    assert cleared == [] and f and f[0].evidence["ratio"] == 0.5
    for i in range(10, 30):
        syn_det.s.apply(p, f"rrc{90 + i % 4}|192.0.2.{i + 1}", "A", tuple(S.normal_path(i, S.A)))
    f, cleared, _ = syn_det.tick_visibility(1410)
    assert f == [] and cleared == [("SYN-A", p)]


def test_hijacked_peers_do_not_count_as_withdrawn(syn_det, cfg):
    p = "198.18.0.0/22"
    for i in range(30):  # route still present, just a different origin
        syn_det.s.apply(p, f"rrc{90 + i % 4}|192.0.2.{i + 1}", "A", (S.PEERS[i]["asn"], S.HIJ1))
    syn_det.dirty.add(p)
    f, _, rows = syn_det.tick_visibility(0)
    assert rows[0]["seen"] == 10   # the dashboard shows only 10 peers reach the right origin ...
    f2, _, _ = syn_det.tick_visibility(cfg.detect["visibility_hold_s"] + 10)
    assert f == [] and f2 == []    # ... but no visibility alert: the origin detectors own this signal


def test_peer_down_does_not_count_as_withdrawal(syn_det):
    p = "198.18.16.0/22"
    for i in range(25):
        syn_det.s.peer_down(f"rrc{90 + i % 4}|192.0.2.{i + 1}")
    syn_det.dirty.add(p)
    f, _, rows = syn_det.tick_visibility(10_000)
    f2, _, _ = syn_det.tick_visibility(20_000)
    assert f == [] and f2 == [] and rows[0]["baseline"] == 15 and rows[0]["seen"] == 15


# ---------------------------------------------------------------- regressions from the critique pass
def test_forged_origin_by_ris_peer_is_flagged(syn_det):
    # a RIS peer claims a direct adjacency to the origin it never had, on a NEW more-specific: medium
    f = kinds(syn_det, ris(1, 11, "198.18.5.0/24", [64999, S.A]))
    assert ("new_upstream", 64999, "medium") in [(x.kind, x.actor_asn, x.severity) for x in f]
    # the same new adjacency on a known prefix is routine (IXP route servers are transparent): info
    f = kinds(syn_det, ris(2, 11, "198.18.0.0/22", [64999, S.A]))
    assert [(x.kind, x.severity) for x in f] == [("new_upstream", "info")]


def test_as_set_paths_skip_adjacency_checks(syn_det):
    # mid-path AS_SET must not create a fake adjacency, and an AS_SET origin is RPKI NONE (invalid if covered)
    assert kinds(syn_det, ris(1, 12, "198.18.0.0/22", [S.PEERS[12]["asn"], [S.CLIQUE[0], 65000], S.U1, S.A])) == []
    f = kinds(syn_det, ris(2, 12, "198.18.0.0/22", [S.PEERS[12]["asn"], S.U1, [S.A]]))
    assert [x.kind for x in f] == ["rpki_invalid"] and f[0].evidence["rpki"]["reason"] == "as-set-origin"


def test_path_poisoning_is_not_a_new_upstream(syn_det):
    assert kinds(syn_det, ris(1, 13, "198.18.0.0/22", [S.PEERS[13]["asn"], S.CLIQUE[0], S.A, 65200, S.A])) == []


def test_clique_sibling_is_not_a_leaker(syn_state, syn_rpki, cfg):
    from bgpwatch.detectors import Detectors
    syn_state.clique_siblings = {65530}   # e.g. Lumen AS3549 next to AS3356
    det = Detectors(syn_state, syn_rpki, cfg.detect)
    path = [S.PEERS[14]["asn"], S.CLIQUE[0], 65530, S.CLIQUE[1], S.U1, S.A]
    assert "route_leak" not in [x.kind for x in kinds(det, ris(1, 14, "198.18.0.0/22", path))]


def test_visibility_alarm_clears_when_too_few_peers_remain(syn_det, cfg):
    p = "198.18.8.0/24"
    for i in range(40):
        syn_det.s.apply(p, f"rrc{90 + i % 4}|192.0.2.{i + 1}", "W", ())
    syn_det.dirty.add(p)
    syn_det.tick_visibility(0)
    f, _, _ = syn_det.tick_visibility(cfg.detect["visibility_hold_s"])
    assert f and f[0].severity == "critical"
    for i in range(25):                      # a collector restarts: 25 peer sessions drop
        syn_det.s.peer_down(f"rrc{90 + i % 4}|192.0.2.{i + 1}")
    f, cleared, _ = syn_det.tick_visibility(1000)
    assert f == [] and cleared == [("SYN-A", p)]


def test_watched_asn_originating_foreign_space(syn_det):
    from bgpwatch.model import RouteEvent
    # SYN-A's AS64500 suddenly originates SYN-B's ROA-covered prefix space outside its own list
    ev = RouteEvent(1.0, "rrc90|192.0.2.1", 65100, "203.0.113.128/25", "A", (65100, S.U1, S.A), S.A)
    f = syn_det.on_outside_announce(ev)
    assert [(x.kind, x.severity, x.actor_asn) for x in f] == [("unexpected_origination", "high", S.A)]
    assert f[0].evidence["roa_asns"] == [S.B]


def test_monitor_survives_malformed_messages(cfg):
    from bgpwatch.monitor import Monitor
    from bgpwatch.rpki import RpkiValidator
    from bgpwatch.store import Store
    mon = Monitor(cfg, S.watchlist(), S.baseline(), RpkiValidator.empty(), Store(":memory:"), source="test")
    for bad in [{"type": "ris_message"}, {"type": "ris_message", "data": {"timestamp": "x"}},
                {"type": "ris_message", "data": {"timestamp": 5, "type": "UPDATE", "host": "rrc00"}},
                {"type": "ris_message", "data": {"timestamp": 6, "type": "UPDATE", "peer": "p", "host": "h",
                                                 "path": ["{1,2}"], "announcements": [{"prefixes": ["10.0.0.0/8"]}]}},
                {"type": "ris_message", "data": {"timestamp": 7, "type": "UPDATE", "peer": "p", "host": "h",
                                                 "announcements": [{"prefixes": ["not-a-prefix"]}]}}]:
        mon.handle(bad)
    assert mon.counts["bad_message"] >= 3
    mon.handle(ris(10, 0, "198.18.0.0/22", S.normal_path(0, S.A)))
    assert mon.counts["announcements"] == 1
