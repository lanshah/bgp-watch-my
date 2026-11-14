"""Alert engine: groups findings into incidents, de-duplicates, applies cooldown, resolves.

Rules (all measurable in the stats the engine keeps):
* One incident per key (detector + network + suspect AS). A hijacker announcing 50 prefixes,
  or one outage hitting 300 prefixes, is one incident with 50/300 prefixes, not 50/300 alerts.
* An incident notifies when it opens, and again only when its severity escalates.
* Severity is reduced by one level while fewer than `min_peers_for_full_severity` RIS peers
  carry the anomaly (a single peer's view is weak evidence).
* An incident resolves when no peer still carries the anomalous route (or visibility has
  recovered above the hysteresis threshold) for 120 s, or when it has had no new evidence
  for `resolve_quiet_s`. If the same key fires again within `cooldown_s` of resolving, the
  old incident is reopened silently instead of paging again (flap suppression).
* At most `max_notifications_per_min` pushes per minute; the rest are counted as suppressed.
"""
from __future__ import annotations

import json
import os
import queue
import threading
import urllib.parse
import urllib.request
from collections import deque

from .config import SEVERITIES, severity_rank
from .explain import explain
from .model import Finding
from .store import Store

RESOLVE_HOLD_S = 120
MAX_EVIDENCE_PREFIXES = 60


def _down(sev: str) -> str:
    return SEVERITIES[max(0, severity_rank(sev) - 1)]


class Incident:
    def __init__(self, f: Finding, source: str):
        self.id: int | None = None
        self.key = f.key
        self.kind = f.kind
        self.network = f.network
        self.actor_asn = f.actor_asn
        self.base_severity = f.severity
        self.severity = f.severity
        self.status = "open"
        self.first_seen = f.ts
        self.last_seen = f.ts
        self.resolved_at: float | None = None
        self.clear_since: float | None = None
        self.title = f.title
        self.active: set[str] = set()          # "prefix|peer" or "prefix" items still showing the anomaly
        self.peers_ever: set[str] = set()
        self.prefixes: dict[str, dict] = {}
        self.findings = 0
        self.reopened = 0
        self.just_reopened = False
        self.rate_limited = False
        self.counted_quiet = False         # counted once in low_severity_not_notified
        self.notified_rank = -1
        self.first_evidence = f.evidence
        self.latest_evidence = f.evidence
        self.worst: dict = {}
        self.source = source
        self.dirty = True

    def peers(self) -> int:
        return len({a.split("|", 1)[1] for a in self.active if "|" in a}) or len(self.peers_ever)


class Notifier:
    name = "base"

    def send(self, inc: dict, text: str) -> tuple[bool, str | None]:
        raise NotImplementedError


class ConsoleNotifier(Notifier):
    name = "console"

    def __init__(self, enabled: bool = True):
        self.enabled = enabled

    def send(self, inc, text):
        if self.enabled:
            print(f"[ALERT {inc['severity'].upper():8}] {text}", flush=True)
        return True, None


class TelegramNotifier(Notifier):
    """Sends via the Telegram Bot API in a background thread (never blocks the monitor)."""
    name = "telegram"

    def __init__(self, token: str, chat_id: str, min_severity: str, store: Store, dashboard_url: str):
        self.token, self.chat_id, self.min = token, chat_id, min_severity
        self.store = store
        self.url = dashboard_url
        self.q: queue.Queue = queue.Queue(maxsize=200)
        threading.Thread(target=self._run, daemon=True, name="telegram").start()

    @classmethod
    def from_env(cls, min_severity: str, store: Store, dashboard_url: str) -> "TelegramNotifier | None":
        tok, chat = os.environ.get("BGPW_TELEGRAM_TOKEN"), os.environ.get("BGPW_TELEGRAM_CHAT_ID")
        return cls(tok, chat, min_severity, store, dashboard_url) if tok and chat else None

    def send(self, inc, text):
        if severity_rank(inc["severity"]) < severity_rank(self.min):
            return False, "below telegram_min_severity"
        try:
            self.q.put_nowait((inc, text))
            return True, "queued"
        except queue.Full:
            return False, "queue full"

    def _run(self):
        while True:
            inc, text = self.q.get()
            body = (f"BGP Watch MY [{inc['severity'].upper()}]\n{text}\n"
                    f"{self.url}/incident.html?id={inc['id']}")
            err = None
            try:
                data = urllib.parse.urlencode({"chat_id": self.chat_id, "text": body,
                                               "disable_web_page_preview": "true"}).encode()
                req = urllib.request.Request(f"https://api.telegram.org/bot{self.token}/sendMessage", data=data)
                with urllib.request.urlopen(req, timeout=20) as r:
                    ok = json.load(r).get("ok", False)
                if not ok:
                    err = "telegram returned ok=false"
            except Exception as e:  # never let a notifier crash the monitor
                err = type(e).__name__  # do not log the URL: it contains the bot token
            try:
                self.store.add_notification(inc["id"], inc["last_seen"], "telegram", inc["severity"], "delivery",
                                            text, err is None, err)
            except Exception:  # keep the sender thread alive even if the database is busy
                pass


class AlertEngine:
    def __init__(self, store: Store, acfg: dict, dcfg: dict, network_names: dict[str, str],
                 notifiers: list[Notifier] | None = None, source: str = "live"):
        self.store = store
        self.cooldown = float(acfg.get("cooldown_s", 900))
        self.quiet = float(acfg.get("resolve_quiet_s", 1800))
        self.max_per_min = int(acfg.get("max_notifications_per_min", 6))
        self.min_peers = int(dcfg.get("min_peers_for_full_severity", 3))
        self.confirm_s = float(dcfg.get("confirm_window_s", 60))
        self.notify_min = acfg.get("notify_min_severity", "medium")
        self.names = network_names
        self.notifiers = notifiers or []
        self.source = source
        self.open: dict[str, Incident] = {}
        self.recent: dict[str, Incident] = {}       # resolved, by key, for flap suppression
        self.index: dict[str, set[str]] = {}         # "prefix|peer" -> incident keys
        self.sent_times: deque = deque()
        self.ris_peers_total = 0
        self.stats = {"findings": 0, "incidents_opened": 0, "incidents_reopened": 0, "notifications": 0,
                      "dedup_suppressed": 0, "cooldown_suppressed": 0, "ratelimit_suppressed": 0,
                      "low_severity_not_notified": 0, "resolved": 0}

    # ------------------------------------------------------------------ input
    def on_finding(self, f: Finding) -> Incident:
        self.stats["findings"] += 1
        inc = self.open.get(f.key)
        status_changed = False
        if inc is None:
            status_changed = True
            old = self.recent.get(f.key)
            if old and f.ts - (old.resolved_at or 0) < self.cooldown:
                inc = old
                inc.status, inc.resolved_at, inc.clear_since = "open", None, None
                inc.reopened += 1
                inc.just_reopened = True
                self.stats["incidents_reopened"] += 1
                del self.recent[f.key]
            else:
                inc = Incident(f, self.source)
                self.stats["incidents_opened"] += 1
            self.open[f.key] = inc
        else:
            self.stats["dedup_suppressed"] += 1
        inc.findings += 1
        inc.last_seen = max(inc.last_seen, f.ts)
        inc.latest_evidence = f.evidence
        inc.clear_since = None
        if severity_rank(f.severity) > severity_rank(inc.base_severity):
            inc.base_severity = f.severity
            inc.title = f.title
        item = f"{f.prefix}|{f.peer}" if f.peer else f.prefix
        inc.active.add(item)
        if f.peer:
            inc.peers_ever.add(f.peer)
            self.index.setdefault(item, set()).add(f.key)
        p = inc.prefixes.setdefault(f.prefix, {"first_seen": f.ts})
        p["last_seen"] = f.ts
        if f.kind == "visibility_drop":
            if f.evidence["ratio"] < p.get("ratio", 2):  # keep the worst reading per prefix
                p.update({k: f.evidence[k] for k in ("seen", "baseline", "ratio")})
            if not inc.worst or f.evidence["ratio"] < inc.worst.get("ratio", 1):
                inc.worst = {"prefix": f.prefix, **{k: f.evidence[k] for k in ("seen", "baseline", "ratio")}}
        elif "rpki" in f.evidence:
            p["rpki"] = f.evidence["rpki"]["state"]
        inc.dirty = True
        self._evaluate(inc, f.ts)
        if inc.dirty and (inc.id is None or status_changed):
            self._persist(inc)  # new or reopened incidents show up on the dashboard at once
        return inc

    def route_changed(self, prefix: str, peer: str) -> None:
        """A new announcement/withdrawal for (prefix, peer) supersedes earlier evidence from it."""
        item = f"{prefix}|{peer}"
        for key in self.index.pop(item, ()):
            inc = self.open.get(key)
            if inc:
                inc.active.discard(item)
                inc.dirty = True

    def peer_down(self, peer: str) -> None:
        suffix = "|" + peer  # peer keys contain "|" themselves (rrc21|192.0.2.1), so strip by length
        for item in [i for i in self.index if i.endswith(suffix)]:
            self.route_changed(item[:-len(suffix)], peer)

    def visibility_cleared(self, network: str, prefix: str) -> None:
        inc = self.open.get(f"visibility_drop|{network}")
        if inc:
            inc.active.discard(prefix)
            inc.dirty = True

    # ------------------------------------------------------------------ evaluation
    def _effective(self, inc: Incident) -> str:
        if inc.kind == "visibility_drop":
            return inc.base_severity
        return inc.base_severity if inc.peers() >= self.min_peers else _down(inc.base_severity)

    def _evaluate(self, inc: Incident, now: float) -> None:
        inc.severity = self._effective(inc)
        r = severity_rank(inc.severity)
        just_reopened, inc.just_reopened = inc.just_reopened, False
        if r <= inc.notified_rank:
            if just_reopened:
                self.stats["cooldown_suppressed"] += 1
            return
        if r < severity_rank(self.notify_min):
            if inc.notified_rank < 0 and not inc.counted_quiet:  # once per incident, not per tick
                inc.counted_quiet = True
                self.stats["low_severity_not_notified"] += 1
            return
        if (inc.kind != "visibility_drop" and inc.notified_rank < 0 and inc.peers() < self.min_peers
                and now - inc.first_seen < self.confirm_s):
            return  # weak evidence: wait for more peers (or the confirmation window) before paging
        reason = "opened" if inc.notified_rank < 0 else "escalated"
        self._persist(inc)
        while self.sent_times and now - self.sent_times[0] > 60:
            self.sent_times.popleft()
        # Critical incidents always push; others wait for budget and are retried on the next tick
        # (notified_rank is only advanced once a notification has actually gone out).
        if len(self.sent_times) >= self.max_per_min and inc.severity != "critical":
            if not inc.rate_limited:
                self.stats["ratelimit_suppressed"] += 1
                inc.rate_limited = True
            return
        inc.rate_limited = False
        inc.notified_rank = r
        self.sent_times.append(now)
        self.stats["notifications"] += 1
        d = self._row(inc)
        text = d["summary"]
        self.store.add_notification(inc.id, now, "dashboard", inc.severity, reason, text, True)
        for n in self.notifiers:
            ok, err = n.send(d, text)
            if n.name != "console" and err not in ("queued",):
                self.store.add_notification(inc.id, now, n.name, inc.severity, reason, text, ok, err)

    def tick(self, now: float) -> None:
        for key, inc in list(self.open.items()):
            if inc.dirty or severity_rank(inc.severity) > inc.notified_rank:
                self._evaluate(inc, now)
            empty = not inc.active
            if empty and inc.clear_since is None:
                inc.clear_since = now
            # Resolve only when no peer still carries the anomaly. A stable hijacked route sends no
            # further UPDATEs, so "no new evidence for a while" must NOT resolve an incident whose
            # routes are still in the RIB. The quiet timer only applies to incidents with nothing active.
            # Info/low incidents (e.g. an operator's own new more-specific) become the new normal after
            # the quiet period even though the route is still announced.
            settled = severity_rank(inc.severity) <= severity_rank("low") and now - inc.last_seen >= self.quiet
            if (empty and (now - inc.clear_since >= RESOLVE_HOLD_S or now - inc.last_seen >= self.quiet)) or settled:
                inc.status, inc.resolved_at = "resolved", now
                self.stats["resolved"] += 1
                del self.open[key]
                self.recent[key] = inc
                inc.dirty = True
            if inc.dirty:
                self._persist(inc)
        for key, inc in list(self.recent.items()):
            if now - (inc.resolved_at or now) > self.cooldown:
                del self.recent[key]

    def flush(self) -> None:
        for inc in list(self.open.values()) + list(self.recent.values()):
            if inc.dirty:
                self._persist(inc)

    # ------------------------------------------------------------------ persistence
    def _row(self, inc: Incident) -> dict:
        prefixes = sorted(inc.prefixes)
        ev = {
            "first": inc.first_evidence,
            "latest": inc.latest_evidence,
            "per_prefix": {p: inc.prefixes[p] for p in prefixes[:MAX_EVIDENCE_PREFIXES]},
            "peers_ever": len(inc.peers_ever),
            "active_items": len(inc.active),
            "worst": inc.worst,
            "base_severity": inc.base_severity,
            "ris_peers_total": self.ris_peers_total,
        }
        d = {"id": inc.id, "key": inc.key, "kind": inc.kind, "network": inc.network, "severity": inc.severity,
             "status": inc.status, "first_seen": inc.first_seen, "last_seen": inc.last_seen,
             "resolved_at": inc.resolved_at, "title": inc.title, "actor_asn": inc.actor_asn, "peers": inc.peers(),
             "prefixes": prefixes, "evidence": ev, "findings": inc.findings, "reopened": inc.reopened,
             "source": inc.source}
        x = explain(d, self.names.get(inc.network, inc.network))
        d["summary"] = x["summary"]
        d["explanation"] = json.dumps(x)
        return d

    def _persist(self, inc: Incident) -> None:
        d = self._row(inc)
        inc.id = self.store.upsert_incident(d)
        inc.dirty = False
