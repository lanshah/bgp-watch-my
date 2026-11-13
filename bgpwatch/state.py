"""In-memory routing state: the per-peer RIB for watched address space plus the baseline."""
from __future__ import annotations

from dataclasses import dataclass, field

from .prefixes import PrefixIndex, net, origin_of


@dataclass
class WatchedPrefix:
    prefix: str
    network: str
    expected_origins: set[int]
    baseline_peers: set[str]
    upstreams: set[int]
    max_path_len: int


@dataclass
class NetworkInfo:
    key: str
    name: str
    asns: set[int]
    covering: list[str]
    upstreams: dict[int, set[int]] = field(default_factory=dict)   # origin -> upstream ASNs seen in baseline


class RouteState:
    def __init__(self, watchlist: dict, baseline: dict):
        self.networks: dict[str, NetworkInfo] = {}
        self.watched: PrefixIndex[WatchedPrefix] = PrefixIndex()
        self.covering: PrefixIndex[str] = PrefixIndex()          # covering prefix -> network key
        self.known_ms: dict[str, set[int]] = {p: set(v["origins"]) for p, v in baseline.get("known_more_specifics", {}).items()}
        self.clique: set[int] = {c["asn"] for c in baseline.get("clique", [])}
        # other ASNs of the same organisations as clique members (CAIDA AS-to-org)
        self.clique_siblings: set[int] = set(baseline.get("clique_siblings", [])) - self.clique
        self.rel: dict[int, dict[str, set[int]]] = {
            int(a): {k: set(v) for k, v in r.items()} for a, r in baseline.get("relationships", {}).items()}
        self.org_of_asn: dict[int, str] = {}
        for n in watchlist["networks"]:
            info = NetworkInfo(n["key"], n["name"], set(n["expected_origins"]), n["covering"])
            self.networks[n["key"]] = info
            for a in info.asns:
                self.org_of_asn[a] = n["key"]
            for c in n["covering"]:
                self.covering.add(c, n["key"])
        bp = baseline.get("prefixes", {})
        rib_seed = baseline.get("rib", {})
        for n in watchlist["networks"]:
            info = self.networks[n["key"]]
            for p, announced_by in n["prefixes"].items():
                b = bp.get(p, {})
                origins = set(announced_by) | {int(o) for o in b.get("origins", {})}
                ups = {int(u) for u in b.get("upstreams", {})}
                wp = WatchedPrefix(p, n["key"], origins, set(rib_seed.get(p, {}).keys()), ups,
                                   int(b.get("max_path_len", 0)))
                self.watched.add(p, wp)
                for o in origins:
                    info.upstreams.setdefault(o, set()).update(ups)
        # RIB: prefix -> peer -> cleaned-path tuple (raw path kept for evidence)
        self.rib: dict[str, dict[str, tuple]] = {}
        for p, peers in rib_seed.items():
            self.rib[p] = {k: tuple(tuple(h) if isinstance(h, list) else h for h in path) for k, path in peers.items()}
        self.down_peers: set[str] = set()

    # ------------------------------------------------------------------ lookup
    def network_for(self, prefix: str) -> str | None:
        c = self.covering.covering(prefix)
        if c:
            return c[0][1]
        w = self.watched.covering(prefix)
        return w[0][1].network if w else None

    def watched_cover(self, prefix: str) -> list[WatchedPrefix]:
        return [w for _, w in self.watched.covering(prefix)]

    # ------------------------------------------------------------------ RIB updates
    def apply(self, prefix: str, peer: str, kind: str, path: tuple) -> tuple | None:
        """Apply an event; return the previous path for (prefix, peer) if there was one."""
        if kind == "A":
            routes = self.rib.setdefault(prefix, {})
            prev = routes.get(peer)
            routes[peer] = path
            self.down_peers.discard(peer)
            return prev
        routes = self.rib.get(prefix)
        if not routes:
            return None
        prev = routes.pop(peer, None)
        if not routes and self.watched.get(prefix) is None:
            del self.rib[prefix]  # don't keep empty entries for withdrawn foreign more-specifics
        return prev

    def peer_down(self, peer: str) -> int:
        self.down_peers.add(peer)
        n = 0
        for routes in self.rib.values():
            if routes.pop(peer, None) is not None:
                n += 1
        return n

    # ------------------------------------------------------------------ visibility
    def visibility(self, wp: WatchedPrefix) -> tuple[int, int, int, int]:
        """Returns (seen, denom, total, present):
        seen    baseline peers that route it to an expected origin (the network's own ASNs or a
                baseline origin) - what the dashboard shows as visibility;
        denom   baseline peers whose RIS session is up;
        total   all peers (baseline or not) routing it to an expected origin;
        present baseline peers with *any* route for it. The visibility detector uses this, so a
                hijack (route present, wrong origin) is left to the origin detectors instead of
                being double-counted as a withdrawal."""
        routes = self.rib.get(wp.prefix, {})
        denom = wp.baseline_peers - self.down_peers
        ok = wp.expected_origins | self.networks[wp.network].asns
        seeing = {p for p, path in routes.items() if origin_of(path) in ok}
        present = denom & routes.keys()
        return len(seeing & denom), len(denom), len(seeing), len(present)

    @staticmethod
    def origin(path: tuple) -> int | None:
        return origin_of(path)

    def all_peers(self) -> int:
        peers = set()
        for routes in self.rib.values():
            peers.update(routes)
        return len(peers)

    def is_watched(self, prefix: str) -> bool:
        return self.watched.get(net(prefix)) is not None
