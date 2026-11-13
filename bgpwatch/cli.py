"""Command-line interface: python -m bgpwatch <command>."""
from __future__ import annotations

import argparse
import asyncio
import json
import shutil
import sys
import threading
import time
import webbrowser
from pathlib import Path

from .config import ROOT, load_config, load_dotenv


def _log(msg: str) -> None:
    print(msg, flush=True)


def cmd_setup(cfg, args):
    from .baseline import build_baseline
    from .rpki import refresh_vrps
    from .sources import HttpClient
    from .watchlist import build_watchlist
    http = HttpClient(cfg)
    _log("[1/3] Verifying ASNs and fetching announced prefixes (RIPEstat, PeeringDB) ...")
    wl = build_watchlist(cfg, http)
    for n in wl["networks"]:
        rej = [a["asn"] for a in n["asns"] if not a["accepted"]]
        _log(f"  {n['name']}: origins {n['expected_origins']}, {len(n['prefixes'])} prefixes, "
             f"{len(n['covering'])} covering" + (f", REJECTED {rej}" if rej else ""))
    _log("[2/3] Building baseline (RIPEstat bgp-state + routing-status, CAIDA AS Rank) ...")
    base = build_baseline(cfg, http, wl, log=_log)
    seeded = sum(1 for p in base["prefixes"].values() if p["peers"])
    _log(f"  baseline: {seeded}/{len(base['prefixes'])} prefixes seeded with per-peer routes; RIS snapshot "
         f"{base['ris_snapshot_times']}; {len(base['known_more_specifics'])} known more-specifics; "
         f"clique {len(base['clique'])} ASes")
    _log("[3/3] Downloading RPKI VRPs ...")
    covering = [c for n in wl["networks"] for c in n["covering"]]
    refresh_vrps(cfg.sources["vrp_urls"], covering, cfg.data_dir / "vrps_watch.json", cfg.user_agent, log=_log)
    _log(f"Done. Network requests made: {http.calls} (cache hits are free). Report: docs/VERIFICATION.md")


def cmd_rpki(cfg, args):
    from .rpki import refresh_vrps
    from .watchlist import load_watchlist
    wl = load_watchlist(cfg)
    covering = [c for n in wl["networks"] for c in n["covering"]]
    refresh_vrps(cfg.sources["vrp_urls"], covering, cfg.data_dir / "vrps_watch.json", cfg.user_agent, log=_log)


def _require_setup(cfg):
    for f in ["watchlist.json", "baseline.json", "vrps_watch.json"]:
        if not (cfg.data_dir / f).exists():
            sys.exit(f"Missing data/{f}. Run `python -m bgpwatch setup` first (needs internet), "
                     f"or try the offline demo: `python -m bgpwatch demo`.")


def _notifiers(cfg, store, console=True):
    from .alerts import ConsoleNotifier, TelegramNotifier
    url = f"http://{cfg.web['host']}:{cfg.web['port']}"
    ns = [ConsoleNotifier(console)]
    tg = TelegramNotifier.from_env(cfg.alerts.get("telegram_min_severity", "high"), store, url)
    if tg:
        ns.append(tg)
        _log("  Telegram notifications: enabled")
    return ns


def _start_web(cfg, store, port=None, open_browser=False):
    from .web import serve
    port = port or cfg.web["port"]
    t = threading.Thread(target=serve, args=(cfg, store, cfg.web["host"], port), daemon=True, name="web")
    t.start()
    url = f"http://{cfg.web['host']}:{port}"
    _log(f"  dashboard: {url}")
    if open_browser:
        webbrowser.open(url)
    return url


def cmd_live(cfg, args):
    from .baseline import load_baseline
    from .live import Recorder, run_live
    from .monitor import Monitor
    from .rpki import RpkiValidator
    from .store import Store
    from .watchlist import load_watchlist
    _require_setup(cfg)
    wl, base = load_watchlist(cfg), load_baseline(cfg)
    rpki = RpkiValidator.load(cfg.data_dir / "vrps_watch.json")
    store = Store(cfg.db_path)
    if args.fresh:
        store.reset()
    mon = Monitor(cfg, wl, base, rpki, store, notifiers=_notifiers(cfg, store), source="live")
    covering = [c for n in wl["networks"] for c in n["covering"]]
    rec = Recorder(cfg.recordings_dir) if args.record else None
    if not args.no_web:
        _start_web(cfg, store, args.port, args.open)
    _log(f"Streaming RIS Live for {len(covering)} covering prefixes"
         + (f" for {args.duration} min" if args.duration else " (Ctrl+C to stop)")
         + (f"; recording to {cfg.recordings_dir}" if rec else ""))
    last_vrp = time.time()

    def on_tick(now):
        nonlocal last_vrp
        mon.wall_tick(now)
        if now - last_vrp > 6 * 3600:  # refresh VRPs every 6 h in long runs
            last_vrp = now
            threading.Thread(target=_refresh_vrps_bg, args=(cfg, covering, mon), daemon=True).start()

    stats = {}
    try:
        stats = asyncio.run(run_live(cfg.sources["ris_live"], cfg.client_name, covering, mon.handle, on_tick, rec,
                                     duration_s=args.duration * 60 if args.duration else None,
                                     tick_s=mon.every, log=_log, origins=sorted(mon.state.org_of_asn),
                                     status=lambda s: store.set_meta(connection=s)))
    except KeyboardInterrupt:
        _log("stopping ...")
    finally:
        mon.finish()
        if rec:
            rec.close()
        store.set_meta(live_stats=stats, stopped_at=time.time())
    c = mon.counts
    _log(f"Live run finished: {c['messages']} messages, {c['announcements']} announcements, "
         f"{c['withdrawals']} withdrawals; incidents opened {mon.engine.stats['incidents_opened']}, "
         f"notifications {mon.engine.stats['notifications']}; connection stats {stats}")
    if rec:
        _log(f"Recorded {rec.lines} messages to: " + ", ".join(str(f) for f in rec.files))
    if args.crosscheck:
        _crosscheck(cfg, mon, wl)


def _refresh_vrps_bg(cfg, covering, mon):
    from .rpki import RpkiValidator, refresh_vrps
    try:
        refresh_vrps(cfg.sources["vrp_urls"], covering, cfg.data_dir / "vrps_watch.json", cfg.user_agent, log=_log)
        new = RpkiValidator.load(cfg.data_dir / "vrps_watch.json")
        mon.det.rpki = new  # reference swap: atomic, on_announce reads it once per event
        mon.store.set_meta(rpki=new.meta)
    except Exception as e:
        _log(f"  VRP refresh failed, keeping old set: {e}")


def _crosscheck(cfg, mon, wl):
    """Outside judge: compare our live per-peer RIB with RIPEstat's own latest bgp-state."""
    from .baseline import peer_key_from_source_id
    from .sources import HttpClient
    http = HttpClient(cfg)
    _log("Cross-check: our live RIB vs RIPEstat bgp-state (fresh) ...")
    exact = close = total = 0
    diffs = []
    ts = set()
    for n in wl["networks"]:
        for a in n["asns"]:
            if not (a["accepted"] and a["announced"]):
                continue
            st = http.ripestat("bgp-state", resource=f"AS{a['asn']}", ttl=0)
            ts.add(st.get("timestamp"))
            theirs = {}
            for r in st["bgp_state"]:
                theirs.setdefault(r["target_prefix"], set()).add(peer_key_from_source_id(r["source_id"]))
            for p, peers in theirs.items():
                wp = mon.state.watched.get(p)
                if wp is None:
                    continue
                ours = {k for k, path in mon.state.rib.get(p, {}).items()
                        if mon.state.origin(path) in wp.expected_origins}
                total += 1
                if ours == peers:
                    exact += 1
                d = len(ours ^ peers)
                if d <= max(2, 0.02 * len(peers)):
                    close += 1
                else:
                    diffs.append((p, len(ours), len(peers), d))
    res = {"prefixes_compared": total, "identical_peer_sets": exact, "within_2pct": close,
           "ripestat_state_times": sorted(t for t in ts if t), "largest_differences": sorted(diffs, key=lambda x: -x[3])[:10]}
    mon.store.set_meta(crosscheck=res)
    _log(json.dumps(res, indent=1))


def cmd_replay(cfg, args):
    from .replay import replay_bundle
    from .store import Store
    path = Path(args.bundle)
    if not (path / "messages.jsonl.gz").exists():
        sys.exit(f"{path} is not a bundle (needs messages.jsonl.gz, watchlist.json, baseline.json). "
                 f"Create one with `python -m bgpwatch synth` or `python -m bgpwatch make-sample`.")
    store = Store(cfg.data_path(args.db))
    if args.serve:
        store.reset()
        _start_web(cfg, store, args.port, args.open)
    mon, res = replay_bundle(cfg, path, store, speed=args.speed, notifiers=_notifiers(cfg, store, not args.quiet),
                             log=_log)
    _log(f"Replayed {res['messages']} messages in {res['wall_s']} s: incidents opened "
         f"{mon.engine.stats['incidents_opened']}, notifications {mon.engine.stats['notifications']}")
    if args.serve:
        _log("Replay finished; dashboard still running (Ctrl+C to stop).")
        _wait_forever()


def _wait_forever():
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass


def cmd_synth(cfg, args):
    from .synthetic import write_bundle
    out = Path(args.out) if args.out else cfg.data_dir / "synthetic" / f"seed-{args.seed}"
    meta = write_bundle(out, args.seed)
    _log(f"Synthetic bundle written to {out}: {meta['messages']} messages, {meta['scenarios']} labelled scenarios")


def cmd_demo(cfg, args):
    from .replay import replay_bundle
    from .store import Store
    from .synthetic import write_bundle
    bdir = cfg.data_dir / "synthetic" / "seed-7"
    if args.sample:
        bdir = Path(args.sample)
    elif not (bdir / "messages.jsonl.gz").exists():
        write_bundle(bdir, 7)
    store = Store(cfg.data_dir / "demo.db")
    store.reset()
    _start_web(cfg, store, args.port, not args.no_browser)
    _log(f"Demo: replaying {bdir.name} at {args.speed}x real time (Ctrl+C to stop)")
    mon, res = replay_bundle(cfg, bdir, store, speed=args.speed, notifiers=_notifiers(cfg, store), log=_log)
    _log(f"Demo replay finished: {res['messages']} messages, incidents {mon.engine.stats['incidents_opened']}. "
         f"Dashboard stays up (Ctrl+C to stop).")
    _wait_forever()


def cmd_make_sample(cfg, args):
    """Package recorded live files + the matching baseline/VRP subset into an offline bundle."""
    import gzip
    from .baseline import load_baseline
    from .prefixes import PrefixIndex, net
    from .replay import read_messages
    from .rpki import RpkiValidator
    from .watchlist import load_watchlist
    files = [Path(f) for f in args.files]
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    wl, base = load_watchlist(cfg), load_baseline(cfg)
    msgs = [m for f in files for m in read_messages(f) if m.get("type") == "ris_message"]
    msgs.sort(key=lambda m: m["data"]["timestamp"])
    touched = set()
    for m in msgs:
        d = m["data"]
        for a in d.get("announcements", []) or []:
            touched.update(a["prefixes"])
        touched.update(d.get("withdrawals", []) or [])
    widx = PrefixIndex()
    for p in base["prefixes"]:
        widx.add(p, p)
    keep = {w for t in touched for _, w in widx.covering(net(t))}
    sub = dict(base)
    sub["prefixes"] = {p: v for p, v in base["prefixes"].items() if p in keep}
    sub["rib"] = {p: v for p, v in base["rib"].items() if p in keep}
    sub["known_more_specifics"] = {p: v for p, v in base["known_more_specifics"].items()
                                   if any(widx.covering(net(p))) and p in touched}
    swl = json.loads(json.dumps(wl))
    for n in swl["networks"]:
        n["prefixes"] = {p: o for p, o in n["prefixes"].items() if p in keep}
    (out / "watchlist.json").write_text(json.dumps(swl, indent=1), encoding="utf-8")
    (out / "baseline.json").write_text(json.dumps(sub), encoding="utf-8")
    shutil.copy(cfg.data_dir / "vrps_watch.json", out / "vrps.json")
    with gzip.open(out / "messages.jsonl.gz", "wt", encoding="utf-8") as fh:
        for m in msgs:
            fh.write(json.dumps(m) + "\n")
    meta = {"kind": "recorded-live", "label": "REAL RIS Live messages recorded by bgp-watch-my",
            "source": "wss://ris-live.ripe.net (RIPE NCC RIS)", "files": [f.name for f in files],
            "messages": len(msgs), "start": msgs[0]["data"]["timestamp"] if msgs else None,
            "end": msgs[-1]["data"]["timestamp"] if msgs else None,
            "baseline_built": base.get("built_at"), "rpki": RpkiValidator.load(out / "vrps.json").meta}
    (out / "bundle.json").write_text(json.dumps(meta, indent=1), encoding="utf-8")
    _log(f"Sample bundle {out}: {len(msgs)} messages, {len(keep)} watched prefixes in baseline subset")


def cmd_evaluate(cfg, args):
    from .evaluate import evaluate, write_report
    seeds = [int(s) for s in args.seeds.split(",")]
    agg = evaluate(cfg, cfg.data_dir / "synthetic", seeds, log=_log)
    write_report(agg, ROOT / "docs" / "ACCURACY.md")
    (ROOT / "docs" / "accuracy.json").write_text(json.dumps(agg, indent=1), encoding="utf-8")
    _log(f"TOTAL: detected {agg['detected']}/{agg['expected_items']}, missed {agg['missed']}, "
         f"false alerts {agg['false_alerts']}. Report: docs/ACCURACY.md")
    if args.strict and (agg["missed"] or agg["false_alerts"]):
        sys.exit(1)


def cmd_serve(cfg, args):
    from .store import Store
    store = Store(cfg.data_path(args.db))
    _start_web(cfg, store, args.port, args.open)
    _wait_forever()


def cmd_export(cfg, args):
    from .export import export_csv
    from .store import Store
    store = Store(cfg.data_path(args.db))
    files = export_csv(store, Path(args.out) if args.out else ROOT / "exports")
    for f, n in files.items():
        _log(f"  {f}: {n} rows")


def cmd_report(cfg, args):
    from .report import write_report
    from .store import Store
    out = Path(args.out)
    write_report(Store(cfg.data_path(args.db)), out, args.title)
    _log(f"Report written to {out}")


def main(argv=None):
    load_dotenv()
    ap = argparse.ArgumentParser(prog="bgpwatch", description="BGP Watch Malaysia - live BGP monitoring")
    ap.add_argument("--config", help="path to bgpwatch.toml")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("setup", help="verify ASNs, fetch prefixes, build baseline, download RPKI VRPs (online)")
    sub.add_parser("rpki-refresh", help="re-download RPKI VRPs")

    p = sub.add_parser("live", help="stream RIS Live and detect in real time")
    p.add_argument("--duration", type=float, help="minutes to run (default: until Ctrl+C)")
    p.add_argument("--record", action="store_true", help="record raw messages to data/recordings")
    p.add_argument("--no-web", action="store_true")
    p.add_argument("--open", action="store_true", help="open the dashboard in a browser")
    p.add_argument("--port", type=int)
    p.add_argument("--fresh", action="store_true", help="clear the live database first")
    p.add_argument("--crosscheck", action="store_true", help="compare final RIB with RIPEstat bgp-state")

    p = sub.add_parser("replay", help="replay a bundle (recorded live data or synthetic)")
    p.add_argument("bundle")
    p.add_argument("--speed", type=float, default=0, help="0 = as fast as possible, N = N x real time")
    p.add_argument("--db", default="data/replay.db")
    p.add_argument("--serve", action="store_true", help="serve the dashboard during/after the replay")
    p.add_argument("--open", action="store_true")
    p.add_argument("--port", type=int)
    p.add_argument("--quiet", action="store_true")

    p = sub.add_parser("synth", help="write the labelled synthetic incident bundle")
    p.add_argument("--seed", type=int, default=7)
    p.add_argument("--out")

    p = sub.add_parser("demo", help="offline demo: replay the synthetic set with the dashboard")
    p.add_argument("--speed", type=float, default=120)
    p.add_argument("--port", type=int)
    p.add_argument("--sample", help="replay this bundle instead (e.g. data/samples/<name>)")
    p.add_argument("--no-browser", action="store_true")

    p = sub.add_parser("make-sample", help="package recorded live files into an offline bundle")
    p.add_argument("files", nargs="+")
    p.add_argument("--out", required=True)

    p = sub.add_parser("evaluate", help="measure detector accuracy on the labelled synthetic set")
    p.add_argument("--seeds", default="7,11,23,42,99")
    p.add_argument("--strict", action="store_true", help="exit 1 on any miss or false alert")

    p = sub.add_parser("serve", help="serve the dashboard for an existing database")
    p.add_argument("--db", default="data/bgpwatch.db")
    p.add_argument("--port", type=int)
    p.add_argument("--open", action="store_true")

    p = sub.add_parser("export-csv", help="export incidents, notifications, visibility to CSV (Power BI)")
    p.add_argument("--db", default="data/bgpwatch.db")
    p.add_argument("--out")

    p = sub.add_parser("report", help="write a Markdown summary of what a run saw")
    p.add_argument("--db", default="data/bgpwatch.db")
    p.add_argument("--out", default="docs/LIVE_RUN.md")
    p.add_argument("--title", default="Live run report")

    args = ap.parse_args(argv)
    cfg = load_config(args.config)
    {"setup": cmd_setup, "rpki-refresh": cmd_rpki, "live": cmd_live, "replay": cmd_replay, "synth": cmd_synth,
     "demo": cmd_demo, "make-sample": cmd_make_sample, "evaluate": cmd_evaluate, "serve": cmd_serve,
     "export-csv": cmd_export, "report": cmd_report}[args.cmd](cfg, args)
