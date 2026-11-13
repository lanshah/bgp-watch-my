"""Watch-list verification logic (offline, fake HTTP) and the dashboard API."""
import json
import threading
import urllib.request
from http.server import ThreadingHTTPServer

from bgpwatch.replay import replay_bundle
from bgpwatch.store import Store
from bgpwatch.synthetic import write_bundle
from bgpwatch.watchlist import verify_asn
from bgpwatch.web import make_handler


class FakeHttp:
    def __init__(self, holder, pdb_name):
        self.holder, self.pdb_name = holder, pdb_name

    def ripestat(self, endpoint, **kw):
        return {"holder": self.holder, "announced": True, "_source_url": "https://stat.ripe.net/x"}

    def peeringdb_net(self, asn):
        return {"name": self.pdb_name, "_source_url": "https://www.peeringdb.com/x"} if self.pdb_name else None


def test_verify_accepts_only_malaysian_keyword_match():
    ok = verify_asn(FakeHttp("TTSSB-MY - TM TECHNOLOGY SERVICES SDN. BHD.", None), 4788, ["TM TECHNOLOGY"], {4788})
    assert ok["accepted"] and ok["keyword_match"] == ["TM TECHNOLOGY"]
    # right name but not registered to MY -> rejected
    assert not verify_asn(FakeHttp("DIGI ROMANIA S.A.", None), 8708, ["DIGI"], {4818})["accepted"]
    # registered to MY but holder does not match -> rejected
    assert not verify_asn(FakeHttp("SOMEONE ELSE", "Other"), 4818, ["DIGI"], {4818})["accepted"]
    # PeeringDB name is accepted as the matching evidence
    assert verify_asn(FakeHttp("X", "CelcomDigi"), 4818, ["DIGI"], {4818})["accepted"]


def test_dashboard_api(cfg, tmp_path):
    bdir = tmp_path / "syn"
    write_bundle(bdir, seed=7)
    store = Store(tmp_path / "t.db")
    replay_bundle(cfg, bdir, store, source="synthetic", log=lambda *_: None)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(cfg, store))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"

    def get(p):
        with urllib.request.urlopen(base + p) as r:
            return r.status, r.headers.get("Content-Type"), r.read()

    try:
        st, ct, body = get("/")
        assert st == 200 and "text/html" in ct and b"BGP Watch" in body
        s = json.loads(get("/api/summary")[2])
        assert s["meta"]["mode"] == "synthetic" and len(s["networks"]) == 3
        incs = json.loads(get("/api/incidents")[2])
        assert len(incs) >= 10
        one = json.loads(get(f"/api/incident/{incs[0]['id']}")[2])
        assert set(one["explanation"]) >= {"summary", "why", "meaning", "check", "limits"}
        assert json.loads(get("/api/feed?limit=5")[2])
        st, ct, body = get("/api/export/incidents.csv")
        assert "text/csv" in ct and body.decode("utf-8-sig").startswith("incident_id,")
        assert b"bgpwatch_prefix_visibility_ratio" in get("/metrics")[2]
        try:
            urllib.request.urlopen(base + "/static/../config.py")
            raise AssertionError("path traversal not blocked")
        except urllib.error.HTTPError as e:
            assert e.code == 404
    finally:
        httpd.shutdown()
