"""Replay recorded or synthetic RIS Live streams.

A *bundle* is a directory that makes a replay fully offline and reproducible:
    bundle.json      description, origin (live recording / synthetic), creation time
    watchlist.json   watch list used
    baseline.json    baseline (subset) used
    vrps.json        RPKI VRP subset used
    messages.jsonl.gz  RIS Live envelopes, one per line, in time order
    labels.json      (synthetic only) ground-truth incidents for the accuracy check
"""
from __future__ import annotations

import gzip
import json
import time
from pathlib import Path
from typing import Iterator

from .config import Config
from .monitor import Monitor
from .rpki import RpkiValidator
from .store import Store


def read_messages(path: Path) -> Iterator[dict]:
    opener = gzip.open if str(path).endswith(".gz") else open
    with opener(path, "rt", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                yield json.loads(line)


def load_bundle(path: Path) -> dict:
    b = {"dir": path}
    for name in ["bundle", "watchlist", "baseline", "labels"]:
        f = path / f"{name}.json"
        if f.exists():
            b[name] = json.loads(f.read_text(encoding="utf-8"))
    vf = path / "vrps.json"
    b["rpki"] = RpkiValidator.load(vf) if vf.exists() else RpkiValidator.empty()
    b["messages"] = path / "messages.jsonl.gz"
    return b


def replay(cfg: Config, monitor: Monitor, messages: Iterator[dict], speed: float = 0.0,
           tail_s: float = 0.0, log=print) -> dict:
    """Feed messages to the monitor. speed=0 -> as fast as possible; speed=N -> N x real time.
    `tail_s` advances the event clock after the last message so hold timers can expire."""
    n = 0
    first_ts = last_ts = None
    wall0 = time.time()
    for msg in messages:
        if msg.get("type") != "ris_message":
            continue
        ts = float(msg["data"]["timestamp"])
        if first_ts is None:
            first_ts = ts
        if speed > 0:
            due = wall0 + (ts - first_ts) / speed
            while time.time() < due:
                time.sleep(min(0.25, due - time.time()))
                monitor.advance(first_ts + (time.time() - wall0) * speed)
        monitor.handle(msg)
        last_ts = ts
        n += 1
    if last_ts is not None and tail_s:
        step = monitor.every
        t = last_ts
        while t < last_ts + tail_s:
            t += step
            monitor.advance(t)
    monitor.finish()
    return {"messages": n, "first_ts": first_ts, "last_ts": last_ts, "wall_s": round(time.time() - wall0, 2)}


def replay_bundle(cfg: Config, bundle_dir: Path, store: Store, speed: float = 0.0, notifiers=None,
                  source: str | None = None, tail_s: float = 600, log=print) -> tuple[Monitor, dict]:
    b = load_bundle(bundle_dir)
    src = source or b.get("bundle", {}).get("kind", "replay")
    store.reset()
    mon = Monitor(cfg, b["watchlist"], b["baseline"], b["rpki"], store, notifiers=notifiers, source=src)
    store.set_meta(bundle=b.get("bundle", {}), replay_of=str(bundle_dir.name))
    res = replay(cfg, mon, read_messages(b["messages"]), speed=speed, tail_s=tail_s, log=log)
    store.set_meta(replay_result=res)
    return mon, res
