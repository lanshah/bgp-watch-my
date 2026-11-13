"""Labelled SYNTHETIC incident set for testing and offline demos.

Everything here is fictional and uses reserved numbers so it can never be mistaken for a
real event:
  * ASNs from the documentation ranges (RFC 5398: 64496-64511, 65536-65551) and the
    private-use range (RFC 6996) for the fictional RIS peers.
  * Prefixes from 198.18.0.0/15 (RFC 2544 benchmarking), 203.0.113.0/24 (TEST-NET-3,
    RFC 5737) and 2001:db8::/32 (RFC 3849).
  * Collector hostnames end in ".synthetic".

The generator builds a baseline (40 peers, every prefix fully visible), a background of
benign churn, and 16 scripted scenarios with ground-truth labels: what *should* be detected
and which scenarios are benign and must not page anyone.
"""
from __future__ import annotations

import gzip
import json
import random
from pathlib import Path

T0 = 1767225600.0  # 2026-01-01 00:00:00 UTC (fictional timeline)
SLOT = 1800        # each scenario gets its own 30-minute slot

A, A2, B, C = 64500, 64501, 64502, 64503            # fictional "telcos" (A2 = A's sibling ASN)
U1, U2 = 65536, 65537                               # their transit providers
CLIQUE = [65540, 65541, 65542]                      # fictional transit-free clique
HIJ1, HIJ2 = 64510, 64511                           # fictional hijackers
LEAKER, NEWUP, CUSTOMER = 65545, 65546, 65547       # leaker, unknown upstream, A's customer

NETWORKS = {
    "SYN-A": {"name": "Synthetic Telco A", "asns": [A, A2],
              "prefixes": {"198.18.0.0/22": [A], "198.18.4.0/22": [A], "198.18.8.0/24": [A]}},
    "SYN-B": {"name": "Synthetic Telco B", "asns": [B],
              "prefixes": {"198.18.16.0/22": [B], "198.18.20.0/23": [B], "203.0.113.0/24": [B]}},
    "SYN-C": {"name": "Synthetic Research Net C", "asns": [C],
              "prefixes": {"198.18.32.0/22": [C], "2001:db8:100::/40": [C]}},
}
VRPS = [
    {"asn": A, "prefix": "198.18.0.0/22", "maxLength": 22, "ta": "synthetic"},
    {"asn": A2, "prefix": "198.18.0.0/22", "maxLength": 22, "ta": "synthetic"},
    {"asn": A, "prefix": "198.18.4.0/22", "maxLength": 24, "ta": "synthetic"},
    {"asn": A, "prefix": "198.18.8.0/24", "maxLength": 24, "ta": "synthetic"},
    {"asn": B, "prefix": "198.18.16.0/22", "maxLength": 22, "ta": "synthetic"},
    {"asn": B, "prefix": "198.18.20.0/23", "maxLength": 23, "ta": "synthetic"},
    {"asn": B, "prefix": "203.0.113.0/24", "maxLength": 24, "ta": "synthetic"},
    {"asn": C, "prefix": "2001:db8:100::/40", "maxLength": 48, "ta": "synthetic"},
    # SYN-C's IPv4 /22 deliberately has no ROA (RPKI NotFound case)
]
N_PEERS = 40


def _peers():
    out = []
    for i in range(N_PEERS):
        out.append({"host": f"rrc{90 + i % 4}.synthetic", "ip": f"192.0.2.{i + 1}", "asn": 65100 + i})
    return out


PEERS = _peers()


def _pkey(p):
    return f"{p['host'].split('.')[0]}|{p['ip']}"


def _origin_of_prefix(prefix: str) -> int:
    for n in NETWORKS.values():
        if prefix in n["prefixes"]:
            return n["prefixes"][prefix][0]
    raise KeyError(prefix)


def normal_path(i: int, origin: int, alt: int = 0) -> list[int]:
    return [PEERS[i]["asn"], CLIQUE[(i + alt) % 3], [U1, U2][(i + alt) % 2], origin]


class Gen:
    def __init__(self, seed: int):
        self.rng = random.Random(seed)
        self.msgs: list[tuple[float, dict]] = []
        self.n = 0

    def _msg(self, ts, i, ann=None, wd=None, path=None):
        p = PEERS[i]
        self.n += 1
        d = {"timestamp": round(ts, 2), "peer": p["ip"], "peer_asn": str(p["asn"]), "id": f"syn-{self.n}",
             "host": p["host"], "type": "UPDATE"}
        if ann:
            d.update({"path": path, "origin": "IGP", "announcements": [{"next_hop": p["ip"], "prefixes": ann}],
                      "withdrawals": []})
        else:
            d.update({"withdrawals": wd, "announcements": []})
        self.msgs.append((ts, {"type": "ris_message", "data": d}))

    def announce(self, ts, i, prefix, path):
        self._msg(ts, i, ann=[prefix], path=path)

    def withdraw(self, ts, i, prefix):
        self._msg(ts, i, wd=[prefix])

    def restore(self, ts, i, prefix):
        self.announce(ts, i, prefix, normal_path(i, _origin_of_prefix(prefix)))

    def peer_state(self, ts, i, state):
        p = PEERS[i]
        self.n += 1
        self.msgs.append((ts, {"type": "ris_message", "data": {
            "timestamp": round(ts, 2), "peer": p["ip"], "peer_asn": str(p["asn"]), "id": f"syn-{self.n}",
            "host": p["host"], "type": "RIS_PEER_STATE", "state": state}}))

    def jitter(self, base, spread=20.0):
        return base + self.rng.uniform(0, spread)

    def peers(self, k):
        return self.rng.sample(range(N_PEERS), k)


def build(seed: int = 7) -> dict:
    g = Gen(seed)
    labels = []

    def slot(n):
        return T0 + 600 + n * SLOT  # first 10 min are quiet baseline

    def label(n, sid, name, expected, benign=False, note=""):
        labels.append({"id": sid, "name": name, "start": slot(n), "end": slot(n) + SLOT - 60,
                       "expected": expected, "benign": benign, "note": note})

    # S1 exact-prefix origin hijack, RPKI invalid
    s = slot(0)
    ps = g.peers(25)
    for i in ps:
        g.announce(g.jitter(s), i, "198.18.0.0/22", [PEERS[i]["asn"], CLIQUE[i % 3], HIJ1])
    for i in ps:
        g.restore(g.jitter(s + 600), i, "198.18.0.0/22")
    label(0, "S1", "Exact-prefix hijack (MOAS), RPKI invalid",
          [{"kind": "origin_change", "network": "SYN-A", "actor_asn": HIJ1, "min_severity": "critical"}])

    # S2 sub-prefix hijack, RPKI invalid (ROA maxLength 22)
    s = slot(1)
    ps = g.peers(30)
    for i in ps:
        g.announce(g.jitter(s), i, "198.18.17.0/24", [PEERS[i]["asn"], CLIQUE[i % 3], U2, HIJ2])
    for i in ps:
        g.withdraw(g.jitter(s + 700), i, "198.18.17.0/24")
    label(1, "S2", "Sub-prefix hijack, RPKI invalid",
          [{"kind": "more_specific_foreign", "network": "SYN-B", "actor_asn": HIJ2, "min_severity": "critical"}])

    # S3 sub-prefix hijack of space with no ROA (RPKI NotFound)
    s = slot(2)
    ps = g.peers(20)
    for i in ps:
        g.announce(g.jitter(s), i, "198.18.33.0/24", [PEERS[i]["asn"], CLIQUE[i % 3], HIJ1])
    for i in ps:
        g.withdraw(g.jitter(s + 500), i, "198.18.33.0/24")
    label(2, "S3", "Sub-prefix hijack, no ROA (NotFound)",
          [{"kind": "more_specific_foreign", "network": "SYN-C", "actor_asn": HIJ1, "min_severity": "high"}])

    # S4 benign: own more-specific within ROA maxLength (traffic engineering)
    s = slot(3)
    for i in range(N_PEERS):
        g.announce(g.jitter(s, 60), i, "198.18.5.0/24", normal_path(i, A))
    label(3, "S4", "Benign: own more-specific (traffic engineering), RPKI valid",
          [{"kind": "more_specific_own", "network": "SYN-A", "actor_asn": A, "max_severity": "info"}], benign=True)

    # S5 full outage: every peer withdraws for 15 min
    s = slot(4)
    for i in range(N_PEERS):
        g.withdraw(g.jitter(s, 30), i, "198.18.8.0/24")
    for i in range(N_PEERS):
        g.restore(g.jitter(s + 900, 30), i, "198.18.8.0/24")
    label(4, "S5", "Outage: prefix withdrawn everywhere for 15 min",
          [{"kind": "visibility_drop", "network": "SYN-A", "prefix": "198.18.8.0/24", "min_severity": "critical"}])

    # S6 partial visibility loss: half the peers withdraw for 10 min
    s = slot(5)
    ps = g.peers(20)
    for i in ps:
        g.withdraw(g.jitter(s, 30), i, "198.18.20.0/23")
    for i in ps:
        g.restore(g.jitter(s + 600, 30), i, "198.18.20.0/23")
    label(5, "S6", "Partial visibility loss (50 % of peers) for 10 min",
          [{"kind": "visibility_drop", "network": "SYN-B", "prefix": "198.18.20.0/23", "min_severity": "high"}])

    # S7 benign: 60-second flap (shorter than the 180 s hold)
    s = slot(6)
    ps = g.peers(35)
    for i in ps:
        g.withdraw(g.jitter(s, 10), i, "198.18.4.0/22")
    for i in ps:
        g.restore(g.jitter(s + 60, 10), i, "198.18.4.0/22")
    label(6, "S7", "Benign: 60 s withdraw/re-announce flap (normal convergence)", [], benign=True)

    # S8 route leak: clique - leaker - clique
    s = slot(7)
    ps = g.peers(15)
    for i in ps:
        g.announce(g.jitter(s), i, "198.18.0.0/22", [PEERS[i]["asn"], CLIQUE[0], LEAKER, CLIQUE[1], U1, A])
    for i in ps:
        g.restore(g.jitter(s + 900), i, "198.18.0.0/22")
    label(7, "S8", "Route leak (valley): clique -> AS65545 -> clique",
          [{"kind": "route_leak", "network": "SYN-A", "actor_asn": LEAKER, "min_severity": "high"}])

    # S9 route leak: origin's customer carries the route upstream
    s = slot(8)
    ps = g.peers(12)
    for i in ps:
        g.announce(g.jitter(s), i, "198.18.4.0/22", [PEERS[i]["asn"], CLIQUE[i % 3], U2, CUSTOMER, A])
    for i in ps:
        g.restore(g.jitter(s + 800), i, "198.18.4.0/22")
    label(8, "S9", "Route leak: AS64500's customer AS65547 as its upstream",
          [{"kind": "route_leak", "network": "SYN-A", "actor_asn": CUSTOMER, "min_severity": "high"}])

    # S10 new unknown upstream (forged-origin style)
    s = slot(9)
    ps = g.peers(10)
    for i in ps:
        g.announce(g.jitter(s), i, "203.0.113.0/24", [PEERS[i]["asn"], CLIQUE[i % 3], NEWUP, B])
    for i in ps:
        g.restore(g.jitter(s + 700), i, "203.0.113.0/24")
    label(9, "S10", "Origin seen via unknown upstream AS65546 (possible forged-origin hijack)",
          [{"kind": "new_upstream", "network": "SYN-B", "actor_asn": NEWUP, "min_severity": "medium"}])

    # S11 own route RPKI-invalid (more specific than ROA maxLength)
    s = slot(10)
    for i in range(N_PEERS):
        g.announce(g.jitter(s, 60), i, "198.18.18.0/24", normal_path(i, B))
    for i in range(N_PEERS):
        g.withdraw(g.jitter(s + 900, 60), i, "198.18.18.0/24")
    label(10, "S11", "Own more-specific beyond ROA maxLength (RPKI invalid-length)",
          [{"kind": "rpki_invalid", "network": "SYN-B", "actor_asn": B, "min_severity": "high"},
           {"kind": "more_specific_own", "network": "SYN-B", "actor_asn": B, "max_severity": "info"}])

    # S12 flapping sub-prefix hijack: 12 announce/withdraw cycles -> must be ONE incident
    s = slot(11)
    ps = g.peers(6)
    for cyc in range(12):
        t = s + cyc * 100
        for i in ps:
            g.announce(g.jitter(t, 5), i, "198.18.2.0/24", [PEERS[i]["asn"], CLIQUE[i % 3], HIJ2])
        for i in ps:
            g.withdraw(g.jitter(t + 40, 5), i, "198.18.2.0/24")
    label(11, "S12", "Flapping sub-prefix hijack (12 cycles) - one incident, no alert storm",
          [{"kind": "more_specific_foreign", "network": "SYN-A", "actor_asn": HIJ2, "min_severity": "critical",
            "max_notifications": 2}])

    # S13 benign: sibling ASN (authorised by ROA) originates the prefix
    s = slot(12)
    ps = g.peers(20)
    for i in ps:
        g.announce(g.jitter(s), i, "198.18.0.0/22", normal_path(i, A2))
    for i in ps:
        g.restore(g.jitter(s + 600), i, "198.18.0.0/22")
    label(12, "S13", "Benign: sibling ASN of the same operator originates the prefix (ROA-valid)", [], benign=True)

    # S14 weak evidence: a single peer sees an origin change -> detected at reduced severity
    s = slot(13)
    i = g.peers(1)[0]
    g.announce(s + 5, i, "198.18.32.0/22", [PEERS[i]["asn"], HIJ1])
    g.restore(s + 900, i, "198.18.32.0/22")
    label(13, "S14", "Single-peer origin change (weak evidence; should be reduced severity)",
          [{"kind": "origin_change", "network": "SYN-C", "actor_asn": HIJ1, "max_severity": "medium"}])

    # S15 benign: operator starts prepending (same ASes, longer raw path)
    s = slot(14)
    for i in range(N_PEERS):
        g.announce(g.jitter(s, 60), i, "198.18.16.0/22", normal_path(i, B)[:-1] + [B, B, B])
    for i in range(N_PEERS):
        g.restore(g.jitter(s + 900, 60), i, "198.18.16.0/22")
    label(14, "S15", "Benign: AS-path prepending change", [], benign=True)

    # S16 benign: 10 RIS peer sessions go down (their routes vanish, prefixes are fine)
    s = slot(15)
    ps = g.peers(10)
    for i in ps:
        g.peer_state(g.jitter(s, 20), i, "down")
    for i in ps:
        g.peer_state(g.jitter(s + 600, 20), i, "connected")
        for p in [p for n in NETWORKS.values() for p in n["prefixes"]]:
            g.restore(g.jitter(s + 620, 20), i, p)
    label(15, "S16", "Benign: 10 RIS peer sessions down (collector-side, not a prefix outage)", [], benign=True)

    # Background churn across the whole timeline: path changes among known upstreams,
    # duplicate announcements and short single-peer withdrawals.
    end = slot(16)
    all_pfx = [p for n in NETWORKS.values() for p in n["prefixes"]]
    t = T0 + 30
    while t < end:
        i = g.rng.randrange(N_PEERS)
        p = g.rng.choice(all_pfx)
        busy = any(l["start"] - 60 <= t <= l["end"] + 300 and _touches(l, p) for l in labels)
        r = g.rng.random()
        if not busy:
            if r < 0.7:
                g.announce(t, i, p, normal_path(i, _origin_of_prefix(p), alt=g.rng.randrange(3)))
            elif r < 0.85:
                g.withdraw(t, i, p)
                g.restore(t + g.rng.uniform(20, 90), i, p)
            else:
                g.announce(t, i, p, normal_path(i, _origin_of_prefix(p)))
        t += g.rng.expovariate(1 / 15)

    g.msgs.sort(key=lambda x: x[0])
    return {"messages": [m for _, m in g.msgs], "labels": labels, "end": end}


def _touches(label: dict, prefix: str) -> bool:
    sid = label["id"]
    touched = {"S1": ["198.18.0.0/22"], "S4": [], "S5": ["198.18.8.0/24"], "S6": ["198.18.20.0/23"],
               "S7": ["198.18.4.0/22"], "S8": ["198.18.0.0/22"], "S9": ["198.18.4.0/22"],
               "S10": ["203.0.113.0/24"], "S13": ["198.18.0.0/22"], "S14": ["198.18.32.0/22"],
               "S15": ["198.18.16.0/22"], "S16": None}
    t = touched.get(sid, [])
    return True if t is None else prefix in t


def watchlist() -> dict:
    nets = []
    for k, n in NETWORKS.items():
        from .prefixes import top_level
        nets.append({"key": k, "name": n["name"] + " (SYNTHETIC)",
                     "asns": [{"asn": a, "accepted": True, "announced": True, "role": "primary" if j == 0 else "sibling",
                               "holder": "SYNTHETIC"} for j, a in enumerate(n["asns"])],
                     "expected_origins": n["asns"], "prefixes": n["prefixes"],
                     "covering": top_level(list(n["prefixes"]))})
    return {"built_at": "synthetic", "networks": nets}


def baseline() -> dict:
    prefixes, rib = {}, {}
    for k, n in NETWORKS.items():
        for p, origins in n["prefixes"].items():
            o = origins[0]
            rib[p] = {_pkey(PEERS[i]): normal_path(i, o) for i in range(N_PEERS)}
            prefixes[p] = {"network": k, "announced_by": origins, "peers": N_PEERS, "origins": {str(o): N_PEERS},
                           "upstreams": {str(U1): N_PEERS // 2, str(U2): N_PEERS // 2}, "max_path_len": 4}
    return {"built_at": "synthetic", "ris_snapshot_times": ["synthetic"],
            "org_of_asn": {str(a): k for k, n in NETWORKS.items() for a in n["asns"]},
            "prefixes": prefixes, "known_more_specifics": {},
            "clique": [{"asn": a, "name": f"SYNTHETIC-CLIQUE-{a}"} for a in CLIQUE],
            "relationships": {str(A): {"provider": [U1, U2], "peer": [], "customer": [CUSTOMER]},
                              str(A2): {"provider": [U1, U2], "peer": [], "customer": []},
                              str(B): {"provider": [U1, U2], "peer": [], "customer": []},
                              str(C): {"provider": [U1, U2], "peer": [], "customer": []}},
            "rib": rib}


def write_bundle(out: Path, seed: int = 7) -> dict:
    out.mkdir(parents=True, exist_ok=True)
    data = build(seed)
    (out / "watchlist.json").write_text(json.dumps(watchlist(), indent=1), encoding="utf-8")
    (out / "baseline.json").write_text(json.dumps(baseline()), encoding="utf-8")
    (out / "vrps.json").write_text(json.dumps({"meta": {"source": "SYNTHETIC", "buildtime": "synthetic"},
                                               "roas": VRPS}), encoding="utf-8")
    (out / "labels.json").write_text(json.dumps(data["labels"], indent=1), encoding="utf-8")
    with gzip.open(out / "messages.jsonl.gz", "wt", encoding="utf-8") as fh:
        for m in data["messages"]:
            fh.write(json.dumps(m) + "\n")
    meta = {"kind": "synthetic", "seed": seed, "label": "SYNTHETIC TEST DATA - fictional networks, reserved numbers",
            "messages": len(data["messages"]), "scenarios": len(data["labels"]),
            "start": T0, "end": data["end"]}
    (out / "bundle.json").write_text(json.dumps(meta, indent=1), encoding="utf-8")
    return meta
