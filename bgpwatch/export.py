"""CSV export for Power BI / Excel (UTF-8 with BOM so Excel opens it cleanly)."""
from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone
from pathlib import Path

from .store import Store


def _iso(ts):
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M:%S") if ts else ""


def _safe(v):
    """Neutralise spreadsheet formulas (CSV injection): text starting with = + - @ gets a leading '."""
    if isinstance(v, str) and v[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + v
    return v


TABLES = ["incidents", "notifications", "prefix_visibility", "network_health", "updates"]


def export_csv(store: Store, out: Path | None, only: str | None = None) -> dict:
    """Write CSV files to `out`. With out=None, return {name: csv_text} instead (used by the web API,
    so concurrent downloads never share files on disk). `only` limits it to one table."""
    if out is not None:
        out.mkdir(parents=True, exist_ok=True)
    res = {}

    def write(name, header, rows):
        if only and name != only + ".csv":
            return
        rows = [[_safe(c) for c in r] for r in rows]
        if out is None:
            buf = io.StringIO()
            w = csv.writer(buf)
            w.writerow(header)
            w.writerows(rows)
            res[name] = "\ufeff" + buf.getvalue()
            return
        p = out / name
        with open(p, "w", newline="", encoding="utf-8-sig") as fh:
            w = csv.writer(fh)
            w.writerow(header)
            w.writerows(rows)
        res[str(p)] = len(rows)

    incs = store.query("SELECT * FROM incidents ORDER BY first_seen")
    write("incidents.csv",
          ["incident_id", "source", "network", "kind", "severity", "status", "first_seen_utc", "last_seen_utc",
           "resolved_utc", "duration_min", "actor_asn", "peers", "prefix_count", "prefixes", "findings", "reopened",
           "title", "summary"],
          [[i["id"], i["source"], i["network"], i["kind"], i["severity"], i["status"], _iso(i["first_seen"]),
            _iso(i["last_seen"]), _iso(i["resolved_at"]),
            round(((i["resolved_at"] or i["last_seen"]) - i["first_seen"]) / 60, 1),
            i["actor_asn"] or "", i["peers"], len(json.loads(i["prefixes"] or "[]")),
            " ".join(json.loads(i["prefixes"] or "[]")[:20]), i["findings"], i["reopened"], i["title"], i["summary"]]
           for i in incs])
    notes = store.query("SELECT * FROM notifications ORDER BY ts")
    write("notifications.csv", ["incident_id", "time_utc", "channel", "severity", "reason", "delivered", "message"],
          [[n["incident_id"], _iso(n["ts"]), n["channel"], n["severity"], n["reason"], n["delivered"], n["message"]]
           for n in notes])
    ps = store.query("SELECT * FROM prefix_state ORDER BY network, prefix")
    write("prefix_visibility.csv", ["network", "prefix", "peers_seeing", "baseline_peers", "visibility_pct",
                                    "all_peers_seeing", "updated_utc"],
          [[r["network"], r["prefix"], r["seen"], r["baseline"], round(100 * (r["ratio"] or 0), 1), r["total"],
            _iso(r["updated"])] for r in ps])
    ns = store.query("SELECT * FROM network_samples ORDER BY ts")
    write("network_health.csv", ["time_utc", "network", "prefixes", "healthy_prefixes", "avg_visibility_pct",
                                 "messages_total"],
          [[_iso(r["ts"]), r["network"], r["prefixes"], r["healthy"], round(100 * r["avg_ratio"], 2), r["updates"]]
           for r in ns])
    ups = store.query("SELECT ts, network, prefix, kind, origin, peer, collector, flagged FROM updates ORDER BY ts")
    if only and only != "updates":
        ups = []
    write("updates.csv", ["time_utc", "network", "prefix", "type", "origin_asn", "ris_peer", "collector", "flagged"],
          [[_iso(u["ts"]), u["network"], u["prefix"], "announce" if u["kind"] == "A" else "withdraw",
            u["origin"] or "", u["peer"], u["collector"], u["flagged"]] for u in ups])
    return res
