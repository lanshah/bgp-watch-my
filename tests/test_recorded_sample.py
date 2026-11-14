"""Detector tests on REAL data recorded by bgp-watch-my from RIS Live for the six watched
Malaysian networks, each with the matching baseline and RPKI subset:

  * run 1: data/samples/ris-live-2026-11-14       (40 min, 01:41-02:22 MYT, 14 Nov 2026)
  * run 2: data/samples/ris-live-2026-11-14-run2  (58 min, 10:24-11:22 MYT, 14 Nov 2026)

The golden files pin what the current detectors report on these recordings, so any change in
behaviour on real traffic shows up as a test failure that must be reviewed (then the golden files
are regenerated with:  python tests/test_recorded_sample.py --update).
"""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
FIX = Path(__file__).parent / "fixtures"
SAMPLES = {
    "run1": (ROOT / "data" / "samples" / "ris-live-2026-11-14", FIX / "sample_golden.json"),
    "run2": (ROOT / "data" / "samples" / "ris-live-2026-11-14-run2", FIX / "sample_run2_golden.json"),
}


def run_sample(cfg, bundle):
    from bgpwatch.replay import replay_bundle
    from bgpwatch.store import Store
    store = Store(":memory:")
    mon, res = replay_bundle(cfg, bundle, store, log=lambda *_: None)
    incs = store.query("SELECT key, kind, severity, status, peers FROM incidents ORDER BY key")
    notes = store.query("SELECT COUNT(*) n FROM notifications WHERE channel='dashboard'")[0]["n"]
    low_vis = store.query("SELECT COUNT(*) n FROM prefix_state WHERE baseline >= 20 AND ratio < 0.6")[0]["n"]
    return {"messages": res["messages"], "announcements": mon.counts["announcements"],
            "withdrawals": mon.counts["withdrawals"], "bad_messages": mon.counts["bad_message"],
            "rpki": mon.det.rpki_checks, "incidents": incs, "notifications": notes,
            "degraded_prefixes_at_end": low_vis}


@pytest.mark.parametrize("name", SAMPLES)
def test_sample_bundle_is_present(name):
    assert (SAMPLES[name][0] / "messages.jsonl.gz").exists(), f"the committed real-data sample {name} is missing"


def test_run1_quiet_traffic_pages_nobody(cfg):
    r = run_sample(cfg, SAMPLES["run1"][0])
    assert r["messages"] == 1502 and r["bad_messages"] == 0
    assert r["announcements"] > 7000
    # a quiet 40 minutes of the real Malaysian table: nothing should page anyone ...
    assert r["notifications"] == 0
    assert all(i["severity"] in ("info", "low") for i in r["incidents"])
    # ... and no watched prefix should look degraded
    assert r["degraded_prefixes_at_end"] == 0
    assert r["rpki"]["invalid"] == 0


def test_run2_flags_the_real_rpki_invalid_route(cfg):
    # 2401:b000:0:3::/64 from AS18206 (TM) is longer than the /48 maxLength in its ROAs.
    # RIPEstat rpki-validation (Routinator) independently returned invalid_length for it on
    # 2026-11-14; it is the only route in this recording that should page.
    r = run_sample(cfg, SAMPLES["run2"][0])
    assert r["messages"] == 2421 and r["bad_messages"] == 0
    assert r["rpki"]["invalid"] == 1
    assert r["notifications"] == 1
    paged = [i for i in r["incidents"] if i["severity"] not in ("info", "low")]
    assert [i["key"] for i in paged] == ["rpki_invalid|TM|18206|invalid-length"]
    assert r["degraded_prefixes_at_end"] == 0


@pytest.mark.parametrize("name", SAMPLES)
def test_real_traffic_matches_golden(cfg, name):
    bundle, golden = SAMPLES[name]
    assert run_sample(cfg, bundle) == json.loads(golden.read_text(encoding="utf-8"))


if __name__ == "__main__" and "--update" in sys.argv:
    sys.path.insert(0, str(ROOT))
    from bgpwatch.config import load_config
    for bundle, golden in SAMPLES.values():
        golden.parent.mkdir(exist_ok=True)
        golden.write_text(json.dumps(run_sample(load_config(), bundle), indent=1), encoding="utf-8")
        print("golden updated:", golden)
