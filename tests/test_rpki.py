import json
from pathlib import Path

from bgpwatch.rpki import RpkiValidator, Vrp, refresh_vrps


def v(asn, p, ml):
    return Vrp(asn, p, ml, "test")


def test_rfc6811_states():
    r = RpkiValidator([v(64500, "198.18.0.0/22", 23), v(0, "198.18.8.0/24", 24)])
    assert r.validate("198.18.0.0/22", 64500).state == "valid"
    assert r.validate("198.18.2.0/23", 64500).state == "valid"
    res = r.validate("198.18.1.0/24", 64500)
    assert (res.state, res.reason) == ("invalid", "invalid-length")
    res = r.validate("198.18.0.0/22", 64510)
    assert (res.state, res.reason) == ("invalid", "invalid-asn")
    assert r.validate("198.19.0.0/24", 64500).state == "not-found"
    # AS0 ROA: nobody may originate
    assert r.validate("198.18.8.0/24", 0).state == "invalid"
    # AS_SET origin can never be valid when covered
    assert r.validate("198.18.0.0/22", None).reason == "as-set-origin"
    assert "maxLength" in r.validate("198.18.1.0/24", 64500).explain("198.18.1.0/24", 64500)


def test_refresh_filters_to_watched_space(tmp_path: Path):
    src = tmp_path / "vrps.json"
    lines = ['{', '"metadata": {', '"buildtime": "2026-11-13T16:51:58Z"', '},', '"roas": [',
             '{ "asn": 4788, "prefix": "175.136.0.0/13", "maxLength": 24, "ta": "apnic", "expires": 1 },',
             '{ "asn": 4788, "prefix": "175.136.0.0/16", "maxLength": 16, "ta": "apnic", "expires": 1 },',
             '{ "asn": 13335, "prefix": "1.0.0.0/24", "maxLength": 24, "ta": "apnic", "expires": 1 },',
             '{ "asn": 1, "prefix": "175.0.0.0/8", "maxLength": 8, "ta": "apnic", "expires": 1 }',
             ']}']
    src.write_text("\n".join(lines), encoding="utf-8")
    out = tmp_path / "out.json"
    meta = refresh_vrps([src.as_uri()], ["175.136.0.0/14"], out, "test", log=lambda *_: None, min_total=1)
    kept = {r["prefix"] for r in json.loads(out.read_text())["roas"]}
    # covering ROA (/13, /8) and inside ROA (/16) kept, unrelated /24 dropped
    assert kept == {"175.136.0.0/13", "175.136.0.0/16", "175.0.0.0/8"}
    assert meta["buildtime"] == "2026-11-13T16:51:58Z" and meta["global_vrps"] == 4


def test_refresh_refuses_partial_set(tmp_path: Path):
    src = tmp_path / "vrps.json"
    src.write_text('{ "asn": 1, "prefix": "1.0.0.0/24", "maxLength": 24, "ta": "x", "expires": 1 }\n')
    import pytest
    with pytest.raises(RuntimeError):
        refresh_vrps([src.as_uri()], ["1.0.0.0/8"], tmp_path / "o.json", "test", log=lambda *_: None)
