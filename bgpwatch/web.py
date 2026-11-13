"""Local web dashboard + JSON API + Prometheus metrics (standard library only)."""
from __future__ import annotations

import io
import json
import mimetypes
import re
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .config import Config, severity_rank
from .export import TABLES, export_csv
from .store import Store

STATIC = Path(__file__).parent / "static"


def _summary(store: Store) -> dict:
    meta = store.meta()
    nets = meta.get("networks", [])
    ps = store.query("SELECT network, COUNT(*) n, SUM(CASE WHEN baseline>0 THEN 1 ELSE 0 END) nb, "
                     "AVG(CASE WHEN baseline>0 THEN ratio END) avg, "
                     "SUM(CASE WHEN baseline>0 AND ratio < 0.6 THEN 1 ELSE 0 END) degraded "
                     "FROM prefix_state GROUP BY network")
    pmap = {r["network"]: r for r in ps}
    inc = store.query("SELECT network, severity, COUNT(*) n FROM incidents WHERE status='open' GROUP BY network, severity")
    open_by = {}
    for r in inc:
        open_by.setdefault(r["network"], {})[r["severity"]] = r["n"]
    upd = store.query("SELECT network, COUNT(*) n, MAX(ts) last FROM updates GROUP BY network")
    umap = {r["network"]: r for r in upd}
    for n in nets:
        p = pmap.get(n["key"], {})
        n.update({"prefixes": p.get("n", 0), "with_baseline": p.get("nb", 0), "avg_visibility": p.get("avg"),
                  "degraded": p.get("degraded", 0), "open": open_by.get(n["key"], {}),
                  "updates": umap.get(n["key"], {}).get("n", 0), "last_update": umap.get(n["key"], {}).get("last")})
    totals = store.query("SELECT COUNT(*) n, SUM(status='open') open FROM incidents")[0]
    return {"meta": meta, "networks": nets, "incidents": totals, "server_time": time.time()}


def _lim(q: dict, default: int, cap: int) -> int:
    """Clamp a ?limit= to 1..cap (a negative LIMIT means 'unlimited' in SQLite)."""
    try:
        return max(1, min(int(q.get("limit", default)), cap))
    except ValueError:
        return default


def _label(v) -> str:
    return str(v).replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n")


def _metrics(store: Store) -> str:
    out = io.StringIO()
    meta = store.meta()
    c = meta.get("counts", {})
    out.write("# HELP bgpwatch_messages_total RIS Live messages processed\n# TYPE bgpwatch_messages_total counter\n")
    out.write(f"bgpwatch_messages_total {c.get('messages', 0)}\n")
    out.write("# HELP bgpwatch_prefix_visibility_ratio Share of baseline RIS peers seeing the prefix\n"
              "# TYPE bgpwatch_prefix_visibility_ratio gauge\n")
    for r in store.query("SELECT prefix, network, ratio FROM prefix_state WHERE baseline > 0"):
        out.write(f'bgpwatch_prefix_visibility_ratio{{network="{_label(r["network"])}",prefix="{_label(r["prefix"])}"}} {r["ratio"]:.4f}\n')
    out.write("# HELP bgpwatch_open_incidents Open incidents\n# TYPE bgpwatch_open_incidents gauge\n")
    for r in store.query("SELECT network, severity, COUNT(*) n FROM incidents WHERE status='open' GROUP BY network, severity"):
        out.write(f'bgpwatch_open_incidents{{network="{_label(r["network"])}",severity="{_label(r["severity"])}"}} {r["n"]}\n')
    return out.getvalue()


def make_handler(cfg: Config, store: Store):
    class H(BaseHTTPRequestHandler):
        server_version = "bgpwatch"

        def log_message(self, *a):  # quiet
            pass

        def _send(self, code: int, body: bytes, ctype: str, extra: dict | None = None):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def _json(self, obj, code=200):
            self._send(code, json.dumps(obj, default=str).encode(), "application/json")

        def _host_ok(self) -> bool:
            """DNS-rebinding guard: only answer requests addressed to this machine by IP or localhost."""
            host = (self.headers.get("Host") or "").rsplit(":", 1)[0].strip("[]").lower()
            return host in ("127.0.0.1", "localhost", "::1", cfg.web.get("host", "127.0.0.1"))

        def do_GET(self):
            if not self._host_ok():
                return self._json({"error": "forbidden host"}, 403)
            u = urllib.parse.urlparse(self.path)
            q = {k: v[0] for k, v in urllib.parse.parse_qs(u.query).items()}
            path = u.path
            try:
                if path in ("/", "/index.html"):
                    return self._static("index.html")
                if path == "/incident.html":
                    return self._static("incident.html")
                if path.startswith("/static/"):
                    return self._static(path[len("/static/"):])
                if path == "/api/summary":
                    return self._json(_summary(store))
                if path == "/api/feed":
                    since = int(q.get("since", 0))
                    lim = _lim(q, 100, 500)
                    where, args = "WHERE id > ?", [since]
                    if q.get("network"):
                        where += " AND network = ?"
                        args.append(q["network"])
                    if q.get("flagged"):
                        where += " AND flagged = 1"
                    rows = store.query(f"SELECT * FROM updates {where} ORDER BY id DESC LIMIT ?", (*args, lim))
                    return self._json(rows)
                if path == "/api/prefixes":
                    where, args = "", ()
                    if q.get("network"):
                        where, args = "WHERE network = ?", (q["network"],)
                    return self._json(store.query(f"SELECT * FROM prefix_state {where} ORDER BY ratio ASC, prefix"
                                                  " LIMIT ?", (*args, _lim(q, 5000, 5000))))
                if path == "/api/incidents":
                    where, args = [], []
                    if q.get("status"):
                        where.append("status = ?")
                        args.append(q["status"])
                    if q.get("network"):
                        where.append("network = ?")
                        args.append(q["network"])
                    w = ("WHERE " + " AND ".join(where)) if where else ""
                    rows = store.query("SELECT id, kind, network, severity, status, first_seen, last_seen, resolved_at,"
                                       " title, summary, actor_asn, peers, prefixes, findings, reopened, source"
                                       f" FROM incidents {w} ORDER BY last_seen DESC LIMIT ?",
                                       (*args, _lim(q, 200, 1000)))
                    for r in rows:
                        r["prefixes"] = json.loads(r["prefixes"] or "[]")
                    rows.sort(key=lambda r: (r["status"] != "open", -severity_rank(r["severity"]), -r["last_seen"]))
                    return self._json(rows)
                m = re.fullmatch(r"/api/incident/(\d+)", path)
                if m:
                    inc = store.incident(int(m.group(1)))
                    if not inc:
                        return self._json({"error": "not found"}, 404)
                    inc["explanation"] = json.loads(inc["explanation"] or "{}")
                    pf = inc["prefixes"][:50]
                    marks = ",".join("?" * len(pf)) or "''"
                    t0, t1 = inc["first_seen"] - 600, (inc["resolved_at"] or inc["last_seen"]) + 600
                    inc["updates"] = store.query(
                        f"SELECT * FROM updates WHERE prefix IN ({marks}) AND ts BETWEEN ? AND ? ORDER BY ts LIMIT 300",
                        (*pf, t0, t1))
                    if inc["kind"] == "visibility_drop":
                        inc["visibility"] = store.query(
                            f"SELECT ts, prefix, seen, baseline, ratio FROM visibility_samples WHERE prefix IN ({marks})"
                            " AND ts BETWEEN ? AND ? ORDER BY ts", (*pf, t0 - 1800, t1 + 1800))
                    return self._json(inc)
                if path == "/api/notifications":
                    return self._json(store.query(
                        "SELECT n.*, i.title, i.network, i.kind FROM notifications n LEFT JOIN incidents i"
                        " ON i.id = n.incident_id ORDER BY n.ts DESC LIMIT ?", (_lim(q, 200, 1000),)))
                if path == "/api/network_series":
                    return self._json(store.query("SELECT * FROM (SELECT * FROM network_samples WHERE network=?"
                                                  " ORDER BY ts DESC LIMIT ?) ORDER BY ts",
                                                  (q.get("network", ""), _lim(q, 1440, 10080))))
                if path == "/api/prefix":
                    p = q.get("prefix", "")
                    return self._json({
                        "state": store.query("SELECT * FROM prefix_state WHERE prefix=?", (p,)),
                        "samples": store.query("SELECT ts, seen, baseline, ratio FROM visibility_samples WHERE prefix=?"
                                               " ORDER BY ts DESC LIMIT 1440", (p,)),
                        "updates": store.query("SELECT * FROM updates WHERE prefix=? ORDER BY ts DESC LIMIT 100", (p,))})
                m = re.fullmatch(r"/api/export/([a-z_]+)\.csv", path)
                if m:
                    if m.group(1) not in TABLES:
                        return self._json({"error": "unknown export"}, 404)
                    text = export_csv(store, None, only=m.group(1))[f"{m.group(1)}.csv"]
                    return self._send(200, text.encode("utf-8"), "text/csv; charset=utf-8",
                                      {"Content-Disposition": f'attachment; filename="bgpwatch-{m.group(1)}.csv"'})
                if path == "/metrics":
                    return self._send(200, _metrics(store).encode(), "text/plain; version=0.0.4")
                if path == "/healthz":
                    return self._json({"ok": True})
                return self._json({"error": "not found"}, 404)
            except ValueError:
                return self._json({"error": "bad parameter"}, 400)
            except Exception as e:  # keep the dashboard alive on bad input
                return self._json({"error": type(e).__name__}, 500)

        def _static(self, name: str):
            p = (STATIC / name).resolve()
            if STATIC.resolve() not in p.parents or not p.is_file():
                return self._json({"error": "not found"}, 404)
            ctype = mimetypes.guess_type(p.name)[0] or "application/octet-stream"
            if ctype.startswith("text/") or ctype in ("application/javascript",):
                ctype += "; charset=utf-8"
            return self._send(200, p.read_bytes(), ctype)

    return H


def serve(cfg: Config, store: Store, host: str = "127.0.0.1", port: int = 8060) -> None:
    httpd = ThreadingHTTPServer((host, port), make_handler(cfg, store))
    httpd.daemon_threads = True
    httpd.serve_forever()
