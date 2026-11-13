"""The monitor pipeline: RIS message -> RIB update -> detectors -> alert engine -> SQLite.

Uses *event time* (the RIS timestamp) as its clock, so live, recorded and synthetic
streams behave identically and replays are deterministic.
"""
from __future__ import annotations

import dataclasses
import json
import time
from collections import Counter

from .alerts import AlertEngine, Notifier
from .baseline import peer_key_from_ris
from .config import Config
from .detectors import Detectors
from .model import events_from_ris
from .prefixes import net
from .rpki import RpkiValidator
from .state import RouteState
from .store import Store


class Monitor:
    def __init__(self, cfg: Config, watchlist: dict, baseline: dict, rpki: RpkiValidator, store: Store,
                 notifiers: list[Notifier] | None = None, source: str = "live", store_updates: bool = True):
        self.cfg = cfg
        self.store = store
        self.source = source
        self.state = RouteState(watchlist, baseline)
        self.det = Detectors(self.state, rpki, cfg.detect)
        names = {k: n.name for k, n in self.state.networks.items()}
        self.engine = AlertEngine(store, cfg.alerts, cfg.detect, names, notifiers, source)
        self.engine.ris_peers_total = self.state.all_peers()
        self.store_updates = store_updates
        self.every = float(cfg.detect.get("evaluate_every_s", 10))
        self.now = 0.0
        self._next_tick = 0.0
        self._next_sample = 0.0
        self._pending: list[tuple] = []
        self.counts = Counter()
        self.started = time.time()
        self.last_msg_ts = None
        self.clock_offset: float | None = None
        self._next_prune = 0.0
        store.set_meta(mode=source, started_at=self.started, baseline_built=baseline.get("built_at"),
                       ris_snapshot_times=baseline.get("ris_snapshot_times"), rpki=rpki.meta,
                       networks=[{"key": k, "name": n.name, "asns": sorted(n.asns), "covering": len(n.covering)}
                                 for k, n in self.state.networks.items()])
        store.set_prefix_states(self.det.all_visibility_rows(), time.time() if source == "live" else 0, False)

    # ------------------------------------------------------------------ input
    def handle(self, msg: dict) -> None:
        """Handle one RIS Live envelope ({"type": "ris_message", "data": {...}}).
        Malformed messages are counted and skipped; they never raise."""
        try:
            self._handle(msg)
        except (KeyError, ValueError, TypeError, AttributeError, IndexError):
            self.counts["bad_message"] += 1

    def wall_tick(self, wall: float) -> None:
        """Live mode: advance the event clock when no messages arrive, corrected for the
        offset between this PC's clock and RIS timestamps (so a fast or slow Windows clock
        cannot shorten hold timers or confirmation windows)."""
        self.advance(wall - self.clock_offset)

    def _handle(self, msg: dict) -> None:
        if msg.get("type") != "ris_message":
            return
        d = msg["data"]
        ts = float(d["timestamp"])
        if self.source == "live":
            off = time.time() - ts
            self.clock_offset = off if self.clock_offset is None else 0.95 * self.clock_offset + 0.05 * off
        self.advance(ts)
        self.counts["messages"] += 1
        self.last_msg_ts = ts
        if d.get("type") == "RIS_PEER_STATE":
            if d.get("state") == "down":
                peer = peer_key_from_ris(d.get("host", ""), d["peer"])
                self.state.peer_down(peer)
                self.engine.peer_down(peer)
                self.counts["peer_down"] += 1
                self.det.dirty.update(p for p in self.state.rib if self.state.is_watched(p))
            return
        for ev in events_from_ris(d):
            try:
                pfx = str(net(ev.prefix))
            except ValueError:
                self.counts["bad_prefix"] += 1
                continue
            if pfx != ev.prefix:
                ev = dataclasses.replace(ev, prefix=pfx)
            netkey = self.state.network_for(pfx)
            if netkey is None:
                # Outside watched space: only interesting if a watched ASN originates it.
                if ev.kind == "A" and ev.origin in self.state.org_of_asn:
                    self.state.apply(pfx, ev.peer, ev.kind, ev.path)
                    self.engine.route_changed(pfx, ev.peer)
                    for f in self.det.on_outside_announce(ev):
                        self.engine.on_finding(f)
                        self.counts["finding_" + f.kind] += 1
                elif pfx in self.state.rib:  # update/withdrawal superseding an earlier flagged route
                    self.state.apply(pfx, ev.peer, ev.kind, ev.path)
                    self.engine.route_changed(pfx, ev.peer)
                else:
                    self.counts["outside_watch"] += 1
                continue
            self.counts["announcements" if ev.kind == "A" else "withdrawals"] += 1
            self.state.apply(pfx, ev.peer, ev.kind, ev.path)
            self.engine.route_changed(pfx, ev.peer)
            if self.state.watched.get(pfx) is not None:
                self.det.dirty.add(pfx)
            flagged = 0
            if ev.kind == "A":
                for f in self.det.on_announce(ev):
                    self.engine.on_finding(f)
                    self.counts["finding_" + f.kind] += 1
                    flagged = 1
            if self.store_updates:
                self._pending.append((ev.ts, ev.collector, ev.peer, ev.peer_asn, pfx, ev.kind, ev.origin,
                                      json.dumps(list(ev.path)), netkey, flagged, self.source))
        if len(self._pending) >= 500:
            self.store.add_updates(self._pending)
            self._pending = []

    def advance(self, ts: float) -> None:
        """Move the event clock forward, running periodic evaluation as time passes."""
        if ts <= self.now:
            return
        if self._next_tick == 0:
            self._next_tick = ts + self.every
            self._next_sample = ts + 60
        self.now = ts
        while self.now >= self._next_tick:
            self.tick(self._next_tick)
            self._next_tick += self.every

    def tick(self, now: float) -> None:
        findings, cleared, rows = self.det.tick_visibility(now)
        for net_, p in cleared:
            self.engine.visibility_cleared(net_, p)
        for f in findings:
            self.engine.on_finding(f)
            self.counts["finding_" + f.kind] += 1
        self.engine.tick(now)
        sample = now >= self._next_sample
        self.store.set_prefix_states(rows, now, sample)
        if sample:
            self._next_sample = now + 60
            self._network_sample(now)
        if self._pending:
            self.store.add_updates(self._pending)
            self._pending = []
        self.store.set_meta(counts=dict(self.counts), engine=self.engine.stats, event_time=now,
                            last_msg_ts=self.last_msg_ts, rpki_checks=self.det.rpki_checks,
                            clock_offset_s=self.clock_offset)
        if self.source == "live" and time.time() >= self._next_prune:  # retention for long runs
            self._next_prune = time.time() + 3600
            self.store.prune(float(self.cfg.raw.get("storage", {}).get("keep_updates_days", 7)))

    def _network_sample(self, now: float) -> None:
        rows = []
        warn = self.cfg.detect["visibility_warn_ratio"]
        per = {}
        for r in self.store.query("SELECT network, ratio, baseline FROM prefix_state"):
            per.setdefault(r["network"], []).append(r)
        for netkey, rs in per.items():
            rs = [r for r in rs if r["baseline"]]
            if not rs:
                continue
            healthy = sum(1 for r in rs if r["ratio"] >= warn)
            rows.append((now, netkey, len(rs), healthy, sum(r["ratio"] for r in rs) / len(rs), self.counts["messages"]))
        self.store.add_network_samples(rows)

    def finish(self) -> None:
        """Flush state at the end of a replay (runs one last evaluation)."""
        self.tick(self.now)
        self.engine.flush()
