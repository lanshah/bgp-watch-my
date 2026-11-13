"""SQLite storage (WAL mode so the dashboard can read while the monitor writes)."""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS updates (
  id INTEGER PRIMARY KEY, ts REAL, collector TEXT, peer TEXT, peer_asn INTEGER, prefix TEXT,
  kind TEXT, origin INTEGER, path TEXT, network TEXT, flagged INTEGER DEFAULT 0, source TEXT);
CREATE INDEX IF NOT EXISTS ix_updates_ts ON updates(ts);
CREATE INDEX IF NOT EXISTS ix_updates_prefix ON updates(prefix, ts);
CREATE TABLE IF NOT EXISTS incidents (
  id INTEGER PRIMARY KEY, key TEXT, kind TEXT, network TEXT, severity TEXT, status TEXT,
  first_seen REAL, last_seen REAL, resolved_at REAL, title TEXT, summary TEXT, explanation TEXT,
  actor_asn INTEGER, peers INTEGER, prefixes TEXT, evidence TEXT, findings INTEGER, reopened INTEGER DEFAULT 0,
  source TEXT);
CREATE INDEX IF NOT EXISTS ix_incidents_key ON incidents(key, status);
CREATE TABLE IF NOT EXISTS notifications (
  id INTEGER PRIMARY KEY, incident_id INTEGER, ts REAL, channel TEXT, severity TEXT, reason TEXT,
  message TEXT, delivered INTEGER, error TEXT);
CREATE TABLE IF NOT EXISTS prefix_state (
  prefix TEXT PRIMARY KEY, network TEXT, seen INTEGER, baseline INTEGER, total INTEGER, ratio REAL, updated REAL);
CREATE TABLE IF NOT EXISTS visibility_samples (
  ts REAL, prefix TEXT, network TEXT, seen INTEGER, baseline INTEGER, ratio REAL);
CREATE INDEX IF NOT EXISTS ix_vs ON visibility_samples(prefix, ts);
CREATE TABLE IF NOT EXISTS network_samples (
  ts REAL, network TEXT, prefixes INTEGER, healthy INTEGER, avg_ratio REAL, updates INTEGER);
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT);
"""


class Store:
    def __init__(self, path: Path | str):
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self._write_lock = threading.Lock()
        c = self.conn
        c.executescript(SCHEMA)
        c.commit()

    @property
    def conn(self) -> sqlite3.Connection:
        if self.path == ":memory:":
            # an in-memory database exists per connection, so all threads must share one
            if getattr(self, "_mem", None) is None:
                self._mem = sqlite3.connect(":memory:", check_same_thread=False)
                self._mem.row_factory = sqlite3.Row
            return self._mem
        c = getattr(self._local, "c", None)
        if c is None:
            c = sqlite3.connect(self.path, timeout=30, check_same_thread=False)
            c.row_factory = sqlite3.Row
            if self.path != ":memory:":
                c.execute("PRAGMA journal_mode=WAL")
            c.execute("PRAGMA synchronous=NORMAL")
            self._local.c = c
        return c

    # ------------------------------------------------------------------ writes
    def reset(self, keep_meta: bool = False) -> None:
        with self._write_lock:
            for t in ["updates", "incidents", "notifications", "prefix_state", "visibility_samples", "network_samples"]:
                self.conn.execute(f"DELETE FROM {t}")
            if not keep_meta:
                self.conn.execute("DELETE FROM meta")
            self.conn.commit()

    def add_updates(self, rows: list[tuple]) -> None:
        if not rows:
            return
        with self._write_lock:
            self.conn.executemany(
                "INSERT INTO updates(ts,collector,peer,peer_asn,prefix,kind,origin,path,network,flagged,source)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?)", rows)
            self.conn.commit()

    def upsert_incident(self, inc: dict) -> int:
        cols = ["key", "kind", "network", "severity", "status", "first_seen", "last_seen", "resolved_at", "title",
                "summary", "explanation", "actor_asn", "peers", "prefixes", "evidence", "findings", "reopened",
                "source"]
        vals = [inc.get(c) for c in cols]
        vals[cols.index("prefixes")] = json.dumps(inc.get("prefixes", []))
        vals[cols.index("evidence")] = json.dumps(inc.get("evidence", {}), default=str)
        with self._write_lock:
            if inc.get("id"):
                self.conn.execute(f"UPDATE incidents SET {', '.join(c + '=?' for c in cols)} WHERE id=?",
                                  [*vals, inc["id"]])
                rid = inc["id"]
            else:
                cur = self.conn.execute(f"INSERT INTO incidents({', '.join(cols)}) VALUES ({', '.join('?' * len(cols))})",
                                        vals)
                rid = cur.lastrowid
            self.conn.commit()
        return rid

    def add_notification(self, incident_id: int, ts: float, channel: str, severity: str, reason: str,
                         message: str, delivered: bool, error: str | None = None) -> None:
        with self._write_lock:
            self.conn.execute(
                "INSERT INTO notifications(incident_id,ts,channel,severity,reason,message,delivered,error)"
                " VALUES (?,?,?,?,?,?,?,?)", (incident_id, ts, channel, severity, reason, message, int(delivered), error))
            self.conn.commit()

    def set_prefix_states(self, rows: list[dict], ts: float, sample: bool) -> None:
        if not rows:
            return
        with self._write_lock:
            self.conn.executemany(
                "INSERT INTO prefix_state(prefix,network,seen,baseline,total,ratio,updated) VALUES (?,?,?,?,?,?,?)"
                " ON CONFLICT(prefix) DO UPDATE SET seen=excluded.seen, baseline=excluded.baseline,"
                " total=excluded.total, ratio=excluded.ratio, updated=excluded.updated",
                [(r["prefix"], r["network"], r["seen"], r["baseline"], r["total"], r["ratio"], ts) for r in rows])
            if sample:
                self.conn.executemany(
                    "INSERT INTO visibility_samples(ts,prefix,network,seen,baseline,ratio) VALUES (?,?,?,?,?,?)",
                    [(ts, r["prefix"], r["network"], r["seen"], r["baseline"], r["ratio"]) for r in rows])
            self.conn.commit()

    def add_network_samples(self, rows: list[tuple]) -> None:
        with self._write_lock:
            self.conn.executemany("INSERT INTO network_samples(ts,network,prefixes,healthy,avg_ratio,updates)"
                                  " VALUES (?,?,?,?,?,?)", rows)
            self.conn.commit()

    def set_meta(self, **kv) -> None:
        with self._write_lock:
            self.conn.executemany("INSERT INTO meta(k,v) VALUES (?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",
                                  [(k, json.dumps(v, default=str)) for k, v in kv.items()])
            self.conn.commit()

    def prune(self, keep_days: float) -> None:
        cutoff = time.time() - keep_days * 86400
        with self._write_lock:
            self.conn.execute("DELETE FROM updates WHERE ts < ? AND source='live'", (cutoff,))
            self.conn.execute("DELETE FROM visibility_samples WHERE ts < ?", (cutoff,))
            self.conn.execute("DELETE FROM network_samples WHERE ts < ?", (cutoff,))
            self.conn.commit()

    # ------------------------------------------------------------------ reads
    def meta(self) -> dict:
        return {r["k"]: json.loads(r["v"]) for r in self.conn.execute("SELECT k, v FROM meta")}

    def query(self, sql: str, args: tuple = ()) -> list[dict]:
        return [dict(r) for r in self.conn.execute(sql, args)]

    def incident(self, iid: int) -> dict | None:
        rows = self.query("SELECT * FROM incidents WHERE id=?", (iid,))
        if not rows:
            return None
        r = rows[0]
        r["prefixes"] = json.loads(r["prefixes"] or "[]")
        r["evidence"] = json.loads(r["evidence"] or "{}")
        r["notifications"] = self.query("SELECT * FROM notifications WHERE incident_id=? ORDER BY ts", (iid,))
        return r
