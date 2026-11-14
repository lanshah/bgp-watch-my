"""Detector tests on REAL data: 40 minutes of RIS Live messages recorded by bgp-watch-my on
2026-11-14 (01:41-02:22 MYT) for the six watched Malaysian networks, with the matching baseline
and RPKI subset (data/samples/ris-live-2026-11-14).

The golden file pins what the current detectors report on this recording, so any change in
behaviour on real traffic shows up as a test failure that must be reviewed (then the golden file
is regenerated with:  python tests/test_recorded_sample.py --update).
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BUNDLE = ROOT / "data" / "samples" / "ris-live-2026-11-14"
GOLDEN = Path(__file__).parent / "fixtures" / "sample_golden.json"


def run_sample(cfg):
    from bgpwatch.replay import replay_bundle
    from bgpwatch.store import Store
    store = Store(":memory:")
    mon, res = replay_bundle(cfg, BUNDLE, store, log=lambda *_: None)
    incs = store.query("SELECT key, kind, severity, status, peers FROM incidents ORDER BY key")
    notes = store.query("SELECT COUNT(*) n FROM notifications WHERE channel='dashboard'")[0]["n"]
    low_vis = store.query("SELECT COUNT(*) n FROM prefix_state WHERE baseline >= 20 AND ratio < 0.6")[0]["n"]
    return {"messages": res["messages"], "announcements": mon.counts["announcements"],
            "withdrawals": mon.counts["withdrawals"], "bad_messages": mon.counts["bad_message"],
            "rpki": mon.det.rpki_checks, "incidents": incs, "notifications": notes,
            "degraded_prefixes_at_end": low_vis}


def test_sample_bundle_is_present():
    assert (BUNDLE / "messages.jsonl.gz").exists(), "the committed real-data sample is missing"


def test_real_traffic_parses_cleanly_and_pages_nobody(cfg):
    r = run_sample(cfg)
    assert r["messages"] == 1502 and r["bad_messages"] == 0
    assert r["announcements"] > 7000
    # a quiet 40 minutes of the real Malaysian table: nothing should page anyone ...
    assert r["notifications"] == 0
    assert all(i["severity"] in ("info", "low") for i in r["incidents"])
    # ... and no watched prefix should look degraded
    assert r["degraded_prefixes_at_end"] == 0
    assert r["rpki"]["invalid"] == 0


def test_real_traffic_matches_golden(cfg):
    assert run_sample(cfg) == json.loads(GOLDEN.read_text(encoding="utf-8"))


if __name__ == "__main__" and "--update" in sys.argv:
    sys.path.insert(0, str(ROOT))
    from bgpwatch.config import load_config
    GOLDEN.parent.mkdir(exist_ok=True)
    GOLDEN.write_text(json.dumps(run_sample(load_config()), indent=1), encoding="utf-8")
    print("golden updated:", GOLDEN)
