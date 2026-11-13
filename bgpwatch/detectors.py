"""Detectors. Each returns Findings with the evidence a NOC engineer would ask for.

Per announcement:
  origin_change        watched prefix announced with an origin AS not in its baseline (MOAS)
  more_specific_foreign  more-specific of watched space announced by an unexpected origin
  more_specific_own    new more-specific by the network's own ASN (traffic engineering; info)
  rpki_invalid         the network's own route is RPKI-invalid (ROV-enforcing networks will drop it)
  route_leak           valley in the AS path (clique-X-clique, or the origin's customer as its transit)
  new_upstream         origin reached through an AS never seen next to it, unknown to CAIDA too
  path_anomaly         AS path much longer than anything in the baseline for this prefix
Periodic (tick):
  visibility_drop      fewer baseline RIS peers see the prefix than the threshold, for > hold time
"""
from __future__ import annotations

from .model import Finding, RouteEvent
from .prefixes import clean_path, has_as_set, is_poisoned, rov_origin
from .rpki import RpkiValidator
from .state import RouteState, WatchedPrefix


class Detectors:
    def __init__(self, state: RouteState, rpki: RpkiValidator, dcfg: dict):
        self.s = state
        self.rpki = rpki
        self.cfg = dcfg
        self._vis: dict[str, dict] = {}     # prefix -> {"below_since": ts|None, "active": bool}
        self.dirty: set[str] = set()        # watched prefixes touched since last tick
        self.rpki_checks = {"valid": 0, "invalid": 0, "not-found": 0}

    # ================================================================== announcements
    def on_announce(self, ev: RouteEvent) -> list[Finding]:
        s = self.s
        netkey = s.network_for(ev.prefix)
        if netkey is None:
            return []
        info = s.networks[netkey]
        covers = s.watched_cover(ev.prefix)
        exact = covers[0] if covers and covers[0].prefix == ev.prefix else None
        parent = covers[0] if covers and not exact else (covers[1] if len(covers) > 1 else None)
        O = ev.origin
        path = list(ev.path)
        cpath = clean_path(path)
        rov = self.rpki.validate(ev.prefix, rov_origin(path))
        self.rpki_checks[rov.state] += 1
        rpki_ev = {"state": rov.state, "reason": rov.reason, "roas": [v.as_dict() for v in rov.covering[:8]],
                   "text": rov.explain(ev.prefix, O)}
        base_ev = {"prefix": ev.prefix, "origin": O, "path": path, "peer": ev.peer, "peer_asn": ev.peer_asn,
                   "collector": ev.collector, "rpki": rpki_ev}
        own = O in info.asns
        out: list[Finding] = []

        if exact:
            if O not in exact.expected_origins and not own:
                other = s.org_of_asn.get(O) if O is not None else None
                if rov.state == "invalid":
                    sev = "critical"
                elif rov.state == "valid":
                    sev = "low"
                elif other:
                    sev = "medium"
                else:
                    sev = "high"
                out.append(Finding("origin_change", f"origin_change|{netkey}|{O}", netkey, sev, ev.ts, ev.prefix,
                                   ev.peer, f"{ev.prefix} announced by unexpected origin AS{O}",
                                   {**base_ev, "expected_origins": sorted(exact.expected_origins),
                                    "other_watched_network": other}, actor_asn=O))
        else:
            known = s.known_ms.get(ev.prefix, set())
            if O in known:
                pass  # long-standing more-specific seen in the baseline
            elif own:
                out.append(Finding("more_specific_own", f"more_specific_own|{netkey}|{O}", netkey, "info", ev.ts,
                                   ev.prefix, ev.peer, f"New more-specific {ev.prefix} from {info.name}'s own AS{O}",
                                   {**base_ev, "covering_prefix": parent.prefix if parent else None}, actor_asn=O))
            else:
                if rov.state == "invalid":
                    sev = "critical"
                elif rov.state == "valid":
                    sev = "low"
                else:
                    sev = "high"
                out.append(Finding("more_specific_foreign", f"more_specific_foreign|{netkey}|{O}", netkey, sev,
                                   ev.ts, ev.prefix, ev.peer,
                                   f"More-specific {ev.prefix} of {info.name} space announced by AS{O}",
                                   {**base_ev, "covering_prefix": parent.prefix if parent else None,
                                    "covering_origins": sorted(parent.expected_origins) if parent else [],
                                    "known_origins_for_prefix": sorted(known)}, actor_asn=O))

        expected_origin = own or (exact is not None and O in exact.expected_origins) or O in s.known_ms.get(ev.prefix, set())
        if own and rov.state == "invalid":
            out.append(Finding("rpki_invalid", f"rpki_invalid|{netkey}|{O}|{rov.reason}", netkey, "high", ev.ts,
                               ev.prefix, ev.peer, f"{info.name} route {ev.prefix} is RPKI-invalid ({rov.reason})",
                               base_ev, actor_asn=O))

        # Adjacency-based checks need an unambiguous sequence: skip paths with AS_SETs and
        # poisoned paths (origin repeated earlier for traffic engineering).
        if expected_origin and len(cpath) >= 2 and not has_as_set(path) and not is_poisoned(cpath):
            out += self._leak_checks(ev, netkey, cpath, base_ev, exact)
        if exact and expected_origin and exact.max_path_len:
            margin = int(self.cfg.get("path_length_margin", 3))
            if len(cpath) > exact.max_path_len + margin:
                out.append(Finding("path_anomaly", f"path_anomaly|{netkey}|{ev.prefix}", netkey, "low", ev.ts,
                                   ev.prefix, ev.peer,
                                   f"Unusually long AS path ({len(cpath)} ASes) for {ev.prefix}",
                                   {**base_ev, "path_len": len(cpath), "baseline_max_len": exact.max_path_len}))
        return out

    def on_outside_announce(self, ev: RouteEvent) -> list[Finding]:
        """A watched ASN originates a prefix that is not in its watch list (the culprit view:
        a Malaysian network announcing someone else's space, e.g. a fat-fingered static route)."""
        O = ev.origin
        netkey = self.s.org_of_asn.get(O)
        if netkey is None:
            return []
        rov = self.rpki.validate(ev.prefix, rov_origin(list(ev.path)))
        self.rpki_checks[rov.state] += 1
        if rov.state == "valid":
            return []  # authorised by a ROA: a new but legitimate announcement
        sev = "high" if rov.state == "invalid" else "low"
        owners = sorted({v.asn for v in rov.covering})
        return [Finding("unexpected_origination", f"unexpected_origination|{netkey}|{O}", netkey, sev, ev.ts,
                        ev.prefix, ev.peer, f"{self.s.networks[netkey].name}'s AS{O} originates {ev.prefix}, "
                        f"outside its known prefixes",
                        {"prefix": ev.prefix, "origin": O, "path": list(ev.path), "peer": ev.peer,
                         "peer_asn": ev.peer_asn, "collector": ev.collector, "roa_asns": owners,
                         "rpki": {"state": rov.state, "reason": rov.reason,
                                  "roas": [v.as_dict() for v in rov.covering[:8]], "text": rov.explain(ev.prefix, O)}},
                        actor_asn=O)]

    def _leak_checks(self, ev: RouteEvent, netkey: str, p: list[int], base_ev: dict,
                     exact: WatchedPrefix | None) -> list[Finding]:
        s = self.s
        out = []
        O = p[-1]
        # (1) clique sandwich: transit-free clique members peer settlement-free with each other and
        #     buy no transit, so clique -> X -> clique means X re-announced a route it should not have.
        if s.clique:
            for i in range(1, len(p) - 1):
                a, x, b = p[i - 1], p[i], p[i + 1]
                # x must not be a sibling ASN of a clique member (e.g. Lumen AS3549 next to AS3356)
                if a in s.clique and b in s.clique and x not in s.clique and x not in s.clique_siblings:
                    out.append(Finding("route_leak", f"route_leak|{netkey}|{x}", netkey, "high", ev.ts, ev.prefix,
                                       ev.peer, f"Possible route leak by AS{x} (between clique ASes AS{a} and AS{b})",
                                       {**base_ev, "pattern": "clique-sandwich", "leaker": x, "left": a, "right": b},
                                       actor_asn=x))
                    break
        # (2) the origin's own customer appears as its upstream (and is not the RIS peer itself)
        rel = s.rel.get(O)
        U = p[-2]
        if rel and U in rel.get("customer", set()) and U != p[0] and len(p) >= 3:
            out.append(Finding("route_leak", f"route_leak|{netkey}|{U}", netkey, "high", ev.ts, ev.prefix, ev.peer,
                               f"Possible route leak: AS{O}'s customer AS{U} is carrying its route upstream",
                               {**base_ev, "pattern": "customer-as-upstream", "leaker": U}, actor_asn=U))
        # (3) adjacency never seen in the baseline and unknown to CAIDA
        known = set(s.networks[netkey].upstreams.get(O, set()))
        if exact:
            known |= exact.upstreams
        if rel:
            known |= rel.get("provider", set()) | rel.get("peer", set()) | rel.get("customer", set())
        # The RIS peer itself counts too: a peer that suddenly claims a direct adjacency to the origin
        # is exactly what a forged-origin hijack (attacker prepends the real origin) looks like.
        if U not in known and U not in s.networks[netkey].asns:  # sibling ASNs are not 'new'
            # A RIS peer newly adjacent to the origin is routine for a known prefix (IXP route servers are
            # transparent), but on a new more-specific it is the forged-origin sub-prefix pattern.
            sev = "info" if (U == p[0] and exact is not None) else "medium"
            out.append(Finding("new_upstream", f"new_upstream|{netkey}|{O}|{U}", netkey, sev, ev.ts, ev.prefix,
                               ev.peer, f"AS{O} seen through a new upstream AS{U}",
                               {**base_ev, "upstream": U, "baseline_upstreams": sorted(known)[:30],
                                "caida_known": bool(rel)}, actor_asn=U))
        return out

    # ================================================================== visibility
    def tick_visibility(self, now: float) -> tuple[list[Finding], list[tuple[str, str]], list[dict]]:
        """Returns (findings, cleared [(network, prefix)], state rows for changed prefixes)."""
        c = self.cfg
        warn, crit, rec = c["visibility_warn_ratio"], c["visibility_crit_ratio"], c["visibility_recover_ratio"]
        hold, minp = c["visibility_hold_s"], c["visibility_min_baseline_peers"]
        findings, cleared, rows = [], [], []
        todo = set(self.dirty) | {p for p, st in self._vis.items() if st["below_since"] is not None or st["active"]}
        self.dirty.clear()
        for p in todo:
            wp = self.s.watched.get(p)
            if wp is None:
                continue
            seen, denom, total, present = self.s.visibility(wp)
            rows.append({"prefix": p, "network": wp.network, "seen": seen, "baseline": denom, "total": total,
                         "ratio": seen / denom if denom else 1.0})
            ratio = present / denom if denom else 1.0
            st = self._vis.setdefault(p, {"below_since": None, "active": False})
            if denom < minp:
                # Too few baseline peers left to judge (e.g. a collector restarted). Don't keep an
                # old alarm open on data we can no longer evaluate.
                if st["active"]:
                    cleared.append((wp.network, p))
                st["below_since"], st["active"] = None, False
                continue
            if ratio < warn:
                if st["below_since"] is None:
                    st["below_since"] = now
                if now - st["below_since"] >= hold:
                    sev = "critical" if ratio < crit else "high"
                    st["active"] = True
                    findings.append(Finding(
                        "visibility_drop", f"visibility_drop|{wp.network}", wp.network, sev, now, p, "",
                        f"{p} visible to only {present}/{denom} baseline RIS peers ({ratio:.0%})",
                        {"prefix": p, "seen": present, "baseline": denom, "ratio": round(ratio, 3),
                         "below_since": st["below_since"], "hold_s": hold, "warn": warn, "crit": crit,
                         "currently_seeing_any": total}))
            elif ratio >= rec:
                if st["active"]:
                    cleared.append((wp.network, p))
                st["below_since"] = None
                st["active"] = False
            else:  # between warn and recover: hysteresis band, keep current state
                if not st["active"]:
                    st["below_since"] = None
        return findings, cleared, rows

    def all_visibility_rows(self) -> list[dict]:
        rows = []
        for _, wp in self.s.watched.items():
            seen, denom, total, _ = self.s.visibility(wp)
            rows.append({"prefix": wp.prefix, "network": wp.network, "seen": seen, "baseline": denom, "total": total,
                         "ratio": seen / denom if denom else 1.0})
        return rows
