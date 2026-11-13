"""RIS Live websocket client with reconnect, keepalive pings and optional recording.

Protocol (RIS Live manual): connect to wss://ris-live.ripe.net/v1/ws/?client=<id>, send
{"type": "ris_subscribe", "data": {...filters...}}; the server streams {"type": "ris_message"}.
`prefix` accepts an array (each element becomes its own subscription) and `moreSpecific`
defaults to true. A separate subscription to RIS_PEER_STATE tells us when a RIS peer's
session goes down, so its missing routes are not mistaken for a withdrawal.
"""
from __future__ import annotations

import asyncio
import gzip
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

import websockets


class Recorder:
    """Writes every received envelope as one JSON line to hourly-rotated .jsonl.gz files."""

    def __init__(self, directory: Path, prefix: str = "live"):
        self.dir = directory
        self.dir.mkdir(parents=True, exist_ok=True)
        self.prefix = prefix
        self._fh = None
        self._hour = None
        self.files: list[Path] = []
        self.lines = 0

    def write(self, raw: str) -> None:
        hour = datetime.now(timezone.utc).strftime("%Y%m%d-%H")
        if hour != self._hour:
            self.close()
            p = self.dir / f"{self.prefix}-{hour}.jsonl.gz"
            self._fh = gzip.open(p, "at", encoding="utf-8")
            self._hour = hour
            self.files.append(p)
        self._fh.write(raw.rstrip("\n") + "\n")
        self.lines += 1
        if self.lines % 100 == 0:
            self._fh.flush()  # gzip sync-flush: a crash or kill loses at most 100 messages

    def close(self) -> None:
        if self._fh:
            self._fh.close()
            self._fh = None


async def run_live(url: str, client: str, covering: list[str], on_message: Callable[[dict], None],
                   on_tick: Callable[[float], None], recorder: Recorder | None = None,
                   duration_s: float | None = None, tick_s: float = 10, log=print,
                   status: Callable[[dict], None] | None = None, origins: list[int] | None = None) -> dict:
    """Stream until `duration_s` elapses (None = forever). Returns connection statistics.

    `origins` (watched ASNs) each get a `path: "<asn>$"` subscription, so a watched ASN
    announcing a prefix *outside* the watch list is seen too. A message can match several
    subscriptions, so duplicates (same message id) are dropped. A bad message or a failing
    callback is counted and skipped: it never stops the stream."""
    stats = {"connects": 0, "disconnects": 0, "messages": 0, "errors": [], "subscribed": 0, "gaps_s": 0.0,
             "bad_messages": 0, "duplicates": 0, "callback_errors": 0}
    recent_ids: dict[str, None] = {}
    t_end = time.time() + duration_s if duration_s is not None else None
    backoff = 1.0
    full_url = f"{url}?client={client}"
    last_down = None
    while t_end is None or time.time() < t_end:
        try:
            async with websockets.connect(full_url, max_size=2 ** 23, ping_interval=30, ping_timeout=60,
                                          open_timeout=30) as ws:
                stats["connects"] += 1
                if last_down:
                    stats["gaps_s"] += time.time() - last_down
                    last_down = None
                connected_at = time.time()
                await ws.send(json.dumps({"type": "ris_subscribe", "data": {
                    "type": "UPDATE", "prefix": covering, "moreSpecific": True,
                    "socketOptions": {"acknowledge": True}}}))
                await ws.send(json.dumps({"type": "ris_subscribe", "data": {"type": "RIS_PEER_STATE"}}))
                for asn in origins or []:
                    await ws.send(json.dumps({"type": "ris_subscribe", "data": {
                        "type": "UPDATE", "path": f"{int(asn)}$", "require": "announcements"}}))
                log(f"  connected to RIS Live; subscribed to {len(covering)} covering prefixes (+ more-specifics)")
                if status:
                    status({"connected": True, "since": time.time()})
                next_tick = time.time() + tick_s
                while t_end is None or time.time() < t_end:
                    timeout = max(0.1, min(next_tick - time.time(), (t_end - time.time()) if t_end else 1e9))
                    try:
                        raw = await asyncio.wait_for(ws.recv(), timeout=timeout)
                    except asyncio.TimeoutError:
                        raw = None
                    if raw is not None:
                        try:
                            msg = json.loads(raw)
                            t = msg.get("type")
                        except (ValueError, AttributeError):
                            stats["bad_messages"] += 1
                            msg, t = None, None
                        if t == "ris_message":
                            mid = (msg.get("data") or {}).get("id") if isinstance(msg.get("data"), dict) else None
                            if mid and mid in recent_ids:
                                stats["duplicates"] += 1
                            else:
                                if mid:
                                    recent_ids[mid] = None
                                    if len(recent_ids) > 20000:
                                        for k in list(recent_ids)[:10000]:
                                            del recent_ids[k]
                                stats["messages"] += 1
                                if recorder:
                                    recorder.write(raw)
                                try:
                                    on_message(msg)
                                except Exception as e:  # never let one message stop a 24/7 monitor
                                    stats["callback_errors"] += 1
                                    if stats["callback_errors"] <= 5:
                                        log(f"  skipped a message that failed processing: {type(e).__name__}: {e}")
                        elif t == "ris_subscribe_ok":
                            stats["subscribed"] += 1
                        elif t == "ris_error":
                            stats["errors"] = (stats["errors"] + [msg.get("data")])[-20:]
                            log(f"  RIS Live error: {msg.get('data')}")
                    if backoff > 1 and time.time() - connected_at > 60:
                        backoff = 1.0  # only reset after the connection has proved stable
                    if time.time() >= next_tick:
                        try:
                            on_tick(time.time())
                        except Exception as e:
                            stats["callback_errors"] += 1
                            log(f"  periodic evaluation failed: {type(e).__name__}: {e}")
                        next_tick = time.time() + tick_s
        except (OSError, websockets.WebSocketException, asyncio.TimeoutError) as e:
            stats["disconnects"] += 1
            last_down = last_down or time.time()
            if status:
                status({"connected": False, "error": type(e).__name__, "since": time.time()})
            log(f"  RIS Live connection lost ({type(e).__name__}: {e}); retrying in {backoff:.0f}s")
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, 120)
    if recorder:
        recorder.close()
    return stats
