"""Shared data types."""
from __future__ import annotations

from dataclasses import dataclass, field

from .baseline import peer_key_from_ris
from .prefixes import origin_of


@dataclass(frozen=True)
class RouteEvent:
    ts: float
    peer: str            # "rrc21|192.0.2.1"
    peer_asn: int
    prefix: str
    kind: str            # "A" announce | "W" withdraw
    path: tuple = ()
    origin: int | None = None
    collector: str = ""
    msg_id: str = ""


def events_from_ris(data: dict) -> list[RouteEvent]:
    """Normalise one RIS Live `ris_message` UPDATE into per-prefix route events."""
    if data.get("type") != "UPDATE":
        return []
    ts = float(data["timestamp"])
    host = data.get("host", "")
    peer = peer_key_from_ris(host, data["peer"])
    pasn = int(data.get("peer_asn", 0))
    path = tuple(tuple(h) if isinstance(h, list) else int(h) for h in data.get("path", []) or [])
    origin = origin_of(list(path)) if path else None
    out: list[RouteEvent] = []
    for w in data.get("withdrawals", []) or []:
        out.append(RouteEvent(ts, peer, pasn, w, "W", (), None, host, data.get("id", "")))
    for ann in data.get("announcements", []) or []:
        for p in ann.get("prefixes", []):
            out.append(RouteEvent(ts, peer, pasn, p, "A", path, origin, host, data.get("id", "")))
    return out


@dataclass
class Finding:
    """One detector's verdict on one route. Findings are grouped into incidents."""
    kind: str
    key: str                     # incident grouping key
    network: str
    severity: str
    ts: float
    prefix: str
    peer: str
    title: str
    evidence: dict = field(default_factory=dict)
    actor_asn: int | None = None  # the AS the finding is about (suspect origin, leaker, new upstream)
