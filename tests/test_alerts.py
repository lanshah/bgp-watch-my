from bgpwatch.alerts import AlertEngine
from bgpwatch.model import Finding
from bgpwatch.store import Store


def eng(rate=6):
    acfg = {"cooldown_s": 900, "resolve_quiet_s": 1800, "max_notifications_per_min": rate}
    dcfg = {"min_peers_for_full_severity": 3, "confirm_window_s": 60}
    s = Store(":memory:")
    return AlertEngine(s, acfg, dcfg, {"N": "Net"}, [], "test"), s


def f(ts, peer, sev="critical", key="origin_change|N|666", prefix="10.0.0.0/24", kind="origin_change"):
    return Finding(kind, key, "N", sev, ts, prefix, peer, "t", {"rpki": {"state": "invalid"}}, actor_asn=666)


def notes(s):
    return s.query("SELECT reason, severity FROM notifications WHERE channel='dashboard' ORDER BY id")


def test_dedup_one_incident_one_page():
    e, s = eng()
    for i in range(20):
        e.on_finding(f(100 + i, f"rrc00|p{i}"))
    assert len(s.query("SELECT * FROM incidents")) == 1
    assert notes(s) == [{"reason": "opened", "severity": "critical"}]
    assert e.stats["dedup_suppressed"] == 19


def test_weak_evidence_waits_then_pages_reduced():
    e, s = eng()
    e.on_finding(f(100, "rrc00|p1"))
    assert notes(s) == []  # single peer: wait for confirmation
    e.tick(130)
    assert notes(s) == []
    e.tick(170)  # confirmation window over: page at reduced severity
    assert notes(s) == [{"reason": "opened", "severity": "high"}]
    e.on_finding(f(180, "rrc00|p2"))
    e.on_finding(f(181, "rrc00|p3"))  # now 3 peers -> escalates to full severity
    assert notes(s)[-1] == {"reason": "escalated", "severity": "critical"}


def test_resolution_and_silent_reopen():
    e, s = eng()
    for i in range(3):
        e.on_finding(f(100, f"rrc00|p{i}"))
    for i in range(3):
        e.route_changed("10.0.0.0/24", f"rrc00|p{i}")  # peers moved back to the legitimate route
    e.tick(110)
    e.tick(240)
    assert s.query("SELECT status FROM incidents")[0]["status"] == "resolved"
    for i in range(3):
        e.on_finding(f(400, f"rrc00|p{i}"))  # flaps back within the cooldown
    assert s.query("SELECT status, reopened FROM incidents") == [{"status": "open", "reopened": 1}]
    assert len(notes(s)) == 1
    assert e.stats["cooldown_suppressed"] == 1


def test_rate_limit_defers_but_never_loses_alerts():
    e, s = eng(rate=2)
    for k in range(5):
        for i in range(3):
            e.on_finding(f(100 + k, f"rrc00|p{i}", sev="high", key=f"origin_change|N|{k}"))
    assert sum(1 for r in notes(s) if r["reason"] == "opened") == 2
    assert e.stats["ratelimit_suppressed"] == 3
    e.tick(170)   # a minute later the budget is back: deferred incidents page now
    assert sum(1 for r in notes(s) if r["reason"] == "opened") == 4


def test_critical_bypasses_rate_limit():
    e, s = eng(rate=1)
    for i in range(3):
        e.on_finding(f(100, f"rrc00|p{i}", sev="high", key="origin_change|N|1"))
    for i in range(3):
        e.on_finding(f(101, f"rrc00|p{i}", sev="critical", key="origin_change|N|2"))
    assert [r["severity"] for r in notes(s)] == ["high", "critical"]


def test_stable_hijack_stays_open_without_new_updates():
    # critique finding: a stable hijacked route sends no more UPDATEs; it must not auto-resolve
    e, s = eng()
    for i in range(5):
        e.on_finding(f(100, f"rrc00|p{i}"))
    e.tick(100 + 3 * 3600)
    assert s.query("SELECT status FROM incidents")[0]["status"] == "open"


def test_peer_down_clears_that_peers_evidence():
    # critique finding: peer keys contain "|", the old split built a key that never matched
    e, s = eng()
    for i in range(3):
        e.on_finding(f(100, f"rrc21|192.0.2.{i}"))
    for i in range(3):
        e.peer_down(f"rrc21|192.0.2.{i}")
    e.tick(110)
    e.tick(240)
    assert s.query("SELECT status FROM incidents")[0]["status"] == "resolved"


def test_info_incident_settles_after_quiet_period():
    e, s = eng()
    for i in range(5):
        e.on_finding(f(100, f"rrc00|p{i}", sev="info", key="more_specific_own|N|1", kind="more_specific_own"))
    e.tick(100 + 1801)   # still announced by all 5 peers, but it is the new normal now
    assert s.query("SELECT status FROM incidents")[0]["status"] == "resolved"


def test_info_never_pages():
    e, s = eng()
    for i in range(5):
        e.on_finding(f(100, f"rrc00|p{i}", sev="info", key="more_specific_own|N|1", kind="more_specific_own"))
    e.tick(400)
    assert notes(s) == [] and e.stats["low_severity_not_notified"] == 1
