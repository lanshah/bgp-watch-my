"""Outside judge for the per-peer RIB: compare it with RIPEstat's near-real-time looking glass.

RIPEstat `looking-glass` returns, per prefix, the route every RIS route-collector peer holds
*now* (typically seconds old). For a fixed random sample of watched prefixes we compare:
  * the set of RIS peers that have a route (ours vs theirs), and
  * for peers in both sets, whether the AS path is identical.
Run once before streaming (how stale is the RIPEstat bgp-state seed?) and once at the end
(did live RIS updates keep the RIB accurate?). The sample is fixed by a seed so the two
checks compare the same prefixes. Cost: one RIPEstat request per sampled prefix.
"""
from __future__ import annotations

import random
import time

from .prefixes import origin_of
from .sources import HttpClient, SourceError
from .state import RouteState


def _lg_routes(http: HttpClient, prefix: str) -> tuple[dict[str, tuple], str | None]:
    d = http.ripestat("looking-glass", resource=prefix, ttl=0)
    out: dict[str, tuple] = {}
    for rrc in d.get("rrcs", []):
        name = rrc["rrc"].lower()
        for p in rrc.get("peers", []):
            if p.get("prefix") != prefix:
                continue
            path = p.get("as_path", "")
            if "{" in path:          # AS_SET formatting differs between sources: compare presence only
                hops = ("as-set",)
            else:
                hops = tuple(int(h) for h in path.split())
            out[f"{name}|{p['peer']}"] = hops
    return out, d.get("latest_time")


def sample_prefixes(state: RouteState, n: int, seed: int = 1) -> list[str]:
    watched = sorted(wp.prefix for _, wp in state.watched.items() if wp.baseline_peers)
    return random.Random(seed).sample(watched, min(n, len(watched)))


def compare(http: HttpClient, state: RouteState, prefixes: list[str], log=print) -> dict:
    tot = {"prefixes": 0, "identical_peer_sets": 0, "close_peer_sets": 0, "common_peers": 0, "same_path": 0,
           "only_ours": 0, "only_theirs": 0, "lg_times": [], "errors": 0}
    worst = []
    for p in prefixes:
        try:
            theirs, lt = _lg_routes(http, p)
        except SourceError:
            tot["errors"] += 1
            continue
        ours = {k: tuple(v) for k, v in state.rib.get(p, {}).items()}
        a, b = set(ours), set(theirs)
        common = a & b
        same = sum(1 for k in common if theirs[k] == ("as-set",) or tuple(ours[k]) == theirs[k])
        tot["prefixes"] += 1
        tot["identical_peer_sets"] += a == b
        diff = len(a ^ b)
        tot["close_peer_sets"] += diff <= max(2, 0.02 * max(len(b), 1))
        tot["common_peers"] += len(common)
        tot["same_path"] += same
        tot["only_ours"] += len(a - b)
        tot["only_theirs"] += len(b - a)
        if lt:
            tot["lg_times"].append(lt)
        worst.append((p, len(a), len(b), diff, len(common) - same))
    tot["path_agreement_pct"] = round(100 * tot["same_path"] / max(1, tot["common_peers"]), 2)
    tot["identical_pct"] = round(100 * tot["identical_peer_sets"] / max(1, tot["prefixes"]), 1)
    tot["close_pct"] = round(100 * tot["close_peer_sets"] / max(1, tot["prefixes"]), 1)
    lts = sorted(tot.pop("lg_times"))
    tot["lg_time_range"] = [lts[0], lts[-1]] if lts else []
    tot["checked_at"] = time.time()
    tot["largest_differences"] = sorted(worst, key=lambda x: (-x[3], -x[4]))[:8]
    log(f"  looking-glass check on {tot['prefixes']} prefixes: identical peer sets {tot['identical_pct']} %, "
        f"within 2 peers/2 % {tot['close_pct']} %, AS-path agreement on common peers {tot['path_agreement_pct']} % "
        f"({tot['only_ours']} peer routes only in ours, {tot['only_theirs']} only in RIPEstat)")
    return tot


def ingest_check(http: HttpClient, messages: list[dict], prefixes: list[str], log=print) -> dict:
    """Did RIS Live deliver what RIPE archived? For each sampled prefix, compare the (peer, type)
    updates we recorded with RIPEstat `bgp-updates` (built from the RIS MRT archive) over the
    same time window. Announcements are matched per (peer, AS path) within a few seconds."""
    from datetime import datetime, timezone
    ts = [m["data"]["timestamp"] for m in messages]
    t0, t1 = min(ts), max(ts)
    fmt = lambda t: datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
    ours: dict[str, list] = {p: [] for p in prefixes}
    for m in messages:
        d = m["data"]
        if d.get("type") != "UPDATE":
            continue
        for a in d.get("announcements", []) or []:
            for p in a["prefixes"]:
                if p in ours:
                    ours[p].append(("A", d["peer"], tuple(h for h in d.get("path", []) if not isinstance(h, list)), d["timestamp"]))
        for p in d.get("withdrawals", []) or []:
            if p in ours:
                ours[p].append(("W", d["peer"], (), d["timestamp"]))
    tot = {"prefixes": 0, "archived_updates": 0, "recorded_updates": 0, "matched": 0, "window_utc": [fmt(t0), fmt(t1)]}
    for p in prefixes:
        try:
            d = http.ripestat("bgp-updates", resource=p, starttime=fmt(t0), endtime=fmt(t1), ttl=7 * 86400)
        except SourceError:
            continue
        arch = []
        for u in d.get("updates", []):
            a = u.get("attrs", {})
            path = tuple(h for h in a.get("path", []) if not isinstance(h, list))
            t = datetime.strptime(u["timestamp"], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc).timestamp()
            arch.append((u["type"], a.get("source_id", "").split("-", 1)[-1], path if u["type"] == "A" else (), t))
        used = set()
        for kind, peer, path, t in arch:
            for i, (k2, p2, path2, t2) in enumerate(ours[p]):
                if i not in used and k2 == kind and p2 == peer and path2 == path and abs(t2 - t) <= 5:
                    used.add(i)
                    tot["matched"] += 1
                    break
        tot["prefixes"] += 1
        tot["archived_updates"] += len(arch)
        tot["recorded_updates"] += len(ours[p])
    tot["archived_found_in_recording_pct"] = round(100 * tot["matched"] / max(1, tot["archived_updates"]), 1)
    tot["recording_found_in_archive_pct"] = round(100 * tot["matched"] / max(1, tot["recorded_updates"]), 1)
    log(f"  ingest check on {tot['prefixes']} prefixes: archive has {tot['archived_updates']} updates, recording has "
        f"{tot['recorded_updates']}; {tot['archived_found_in_recording_pct']} % of archived updates were received live, "
        f"{tot['recording_found_in_archive_pct']} % of received updates are in the archive")
    return tot
