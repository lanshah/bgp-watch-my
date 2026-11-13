"""End-to-end: replay the labelled synthetic set and score it (the accuracy check runs in CI)."""
import json

from bgpwatch.evaluate import score
from bgpwatch.replay import replay_bundle
from bgpwatch.store import Store
from bgpwatch.synthetic import write_bundle


def quiet(*_):
    pass


def test_synthetic_set_detects_everything_without_false_alerts(cfg, tmp_path):
    bdir = tmp_path / "syn"
    write_bundle(bdir, seed=7)
    store = Store(":memory:")
    _, res = replay_bundle(cfg, bdir, store, source="synthetic", log=quiet)
    sc = score(store, json.loads((bdir / "labels.json").read_text()))
    assert res["messages"] > 2000
    assert sc["missed"] == 0, [r for r in sc["rows"] if not r["detected"]]
    assert sc["false_alerts"] == 0, sc["false_alert_details"]
    assert sc["benign_scenarios_paged"] == []


def test_replay_is_deterministic(cfg, tmp_path):
    bdir = tmp_path / "syn"
    write_bundle(bdir, seed=11)
    out = []
    for _ in range(2):
        store = Store(":memory:")
        replay_bundle(cfg, bdir, store, source="synthetic", log=quiet)
        out.append(store.query("SELECT key, severity, status, first_seen, peers FROM incidents ORDER BY id"))
    assert out[0] == out[1] and out[0]
