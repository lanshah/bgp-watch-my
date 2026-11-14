"""Baseline: what 'normal' looks like for every watched prefix, from raw RIS data.

* RIPEstat bgp-state (per origin ASN) gives every RIS peer's current AS path for every
  prefix that ASN originates. This seeds the per-peer RIB, so visibility is a real count
  of peers from the first second, not something inferred from withdrawal rates.
* RIPEstat routing-status (per covering prefix) lists the more-specifics announced inside
  watched space, including legitimate customer routes with a different origin AS.
* CAIDA AS Rank gives the transit-free clique and inferred provider/peer/customer links of
  each watched origin. Used only by the route-leak heuristic.
"""
from __future__ import annotations

import json
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

from .config import Config
from .prefixes import clean_path, origin_of, upstream_of
from .sources import HttpClient, SourceError


def peer_key_from_source_id(source_id: str) -> str:
    rrc, ip = source_id.split("-", 1)
    return f"rrc{int(rrc):02d}|{ip}"


def peer_key_from_ris(host: str, peer: str) -> str:
    # RIS Live host is e.g. "rrc21.ripe.net"; older docs show "rrc21"
    h = host.split(".", 1)[0]
    return f"{h}|{peer}"


def build_baseline(cfg: Config, http: HttpClient, wl: dict, out: Path | None = None,
                   log=print, refresh_state: bool = False) -> dict:
    out = out or cfg.data_dir / "baseline.json"
    prefixes: dict[str, dict] = {}
    rib: dict[str, dict[str, list]] = {}
    snapshot_times = set()
    org_of_asn = {}
    for n in wl["networks"]:
        for a in n["expected_origins"]:
            org_of_asn[a] = n["key"]
        for p, origins in n["prefixes"].items():
            prefixes[p] = {"network": n["key"], "announced_by": origins}

    announced = [(n["key"], a["asn"]) for n in wl["networks"] for a in n["asns"]
                 if a["accepted"] and a["announced"]]

    def fetch_state(item):
        key, asn = item
        log(f"  bgp-state AS{asn} ({key}) ...")
        return asn, http.ripestat("bgp-state", resource=f"AS{asn}", ttl=0 if refresh_state else 6 * 3600)

    with ThreadPoolExecutor(max_workers=4) as pool:
        for asn, st in pool.map(fetch_state, announced):
            snapshot_times.add(st.get("timestamp"))
            for r in st["bgp_state"]:
                p = r["target_prefix"]
                if p not in prefixes:
                    continue
                rib.setdefault(p, {})[peer_key_from_source_id(r["source_id"])] = r["path"]

    # per-prefix statistics ------------------------------------------------
    for p, info in prefixes.items():
        routes = rib.get(p, {})
        origins = Counter(origin_of(path) for path in routes.values())
        ups = Counter(upstream_of(path) for path in routes.values())
        lengths = [len(clean_path(path)) for path in routes.values()]
        info.update({
            "peers": len(routes),
            "origins": {str(k): v for k, v in origins.items() if k is not None},
            "upstreams": {str(k): v for k, v in ups.items() if k is not None},
            "max_path_len": max(lengths) if lengths else 0,
        })

    # known more-specifics inside watched space -----------------------------
    covering = [(n["key"], c) for n in wl["networks"] for c in n["covering"]]
    known_more_specifics: dict[str, dict] = {}

    def fetch_rs(item):
        key, c = item
        try:
            return key, c, http.ripestat("routing-status", resource=c, ttl=12 * 3600)
        except SourceError as e:
            log(f"  routing-status {c} failed: {e}")
            return key, c, None

    log(f"  routing-status for {len(covering)} covering prefixes ...")
    with ThreadPoolExecutor(max_workers=4) as pool:
        for key, c, rs in pool.map(fetch_rs, covering):
            if not rs:
                continue
            for ms in rs.get("more_specifics", []):
                rec = known_more_specifics.setdefault(ms["prefix"], {"network": key, "origins": []})
                o = int(ms["origin"])
                if o not in rec["origins"]:
                    rec["origins"].append(o)

    # CAIDA relationships ---------------------------------------------------
    rel: dict[str, dict[str, list[int]]] = {}
    clique: dict = {"date": None, "members": []}
    siblings: list[int] = []
    try:
        clique = http.caida_clique()
        try:
            siblings = http.caida_siblings([m["asn"] for m in clique["members"]])
        except SourceError as e:
            log(f"  CAIDA AS-to-org lookup failed ({e}); clique siblings unknown")
        for _, asn in announced:
            links = http.caida_links(asn)
            r = {"provider": [], "peer": [], "customer": []}
            for l in links:
                r.setdefault(l["relationship"], []).append(int(l["asn1"]["asn"]))
            rel[str(asn)] = r
    except SourceError as e:
        log(f"  CAIDA AS Rank unavailable ({e}); route-leak heuristic will use baseline upstreams only")

    base = {
        "built_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "ris_snapshot_times": sorted(t for t in snapshot_times if t),
        "org_of_asn": {str(k): v for k, v in org_of_asn.items()},
        "prefixes": prefixes,
        "known_more_specifics": known_more_specifics,
        "clique": clique["members"],
        "clique_dataset": clique["date"],
        "clique_siblings": siblings,
        "relationships": rel,
        "rib": rib,
        "request_count": http.calls,
    }
    out.write_text(json.dumps(base), encoding="utf-8")
    return base


def load_baseline(cfg: Config, path: Path | None = None) -> dict:
    p = path or cfg.data_dir / "baseline.json"
    return json.loads(p.read_text(encoding="utf-8"))
