"""RPKI route origin validation (RFC 6811) against a public VRP set.

We download the Validated ROA Payloads published by rpki-client (console.rpki-client.org,
fallback rpki.cloudflare.com; both produced by rpki-client from all five RIR trust anchors),
keep only the ROAs that overlap watched address space, and validate locally. This is what
a router does with RTR, without needing a validator of our own, and it means every verdict
can show the exact ROAs it was based on.
"""
from __future__ import annotations

import gzip
import io
import json
import re
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from .prefixes import PrefixIndex, net

ROA_RE = re.compile(r'"asn":\s*(\d+),\s*"prefix":\s*"([^"]+)",\s*"maxLength":\s*(\d+),\s*"ta":\s*"([^"]*)"')
BUILD_RE = re.compile(r'"buildtime":\s*"([^"]+)"')


@dataclass(frozen=True)
class Vrp:
    asn: int
    prefix: str
    max_length: int
    ta: str

    def as_dict(self) -> dict:
        return {"asn": self.asn, "prefix": self.prefix, "maxLength": self.max_length, "ta": self.ta}


@dataclass
class RovResult:
    state: str              # "valid" | "invalid" | "not-found"
    reason: str             # "", "invalid-asn", "invalid-length", "as-set-origin"
    covering: list[Vrp]

    def explain(self, prefix: str, origin: int | None) -> str:
        if self.state == "not-found":
            return f"No ROA covers {prefix}, so RPKI cannot say whether AS{origin} is authorised (NotFound)."
        roas = "; ".join(f"AS{v.asn} {v.prefix} maxLength /{v.max_length} ({v.ta})" for v in self.covering[:5])
        if self.state == "valid":
            return f"A ROA authorises AS{origin} to announce {prefix} (Valid). ROAs: {roas}."
        if self.reason == "invalid-length":
            return (f"AS{origin} is authorised for this address space, but only up to the ROA's maxLength; "
                    f"{prefix} is more specific than allowed (Invalid, length). ROAs: {roas}.")
        if self.reason == "as-set-origin":
            return f"The route ends in an AS_SET, which can never match a ROA (Invalid). ROAs: {roas}."
        return (f"ROAs exist for this space but none authorises AS{origin} (Invalid, wrong origin AS). "
                f"ROAs: {roas}.")


class RpkiValidator:
    def __init__(self, vrps: list[Vrp], meta: dict | None = None):
        self.meta = meta or {}
        self.index: PrefixIndex[list[Vrp]] = PrefixIndex()
        for v in vrps:
            cur = self.index.get(v.prefix)
            if cur is None:
                self.index.add(v.prefix, [v])
            else:
                cur.append(v)
        self.count = len(vrps)

    def validate(self, prefix: str, origin: int | None) -> RovResult:
        n = net(prefix)
        covering = [v for _, vs in self.index.covering(n) for v in vs]
        if not covering:
            return RovResult("not-found", "", [])
        if origin is None:
            return RovResult("invalid", "as-set-origin", covering)
        match_asn = [v for v in covering if v.asn == origin and v.asn != 0]
        if any(n.prefixlen <= v.max_length for v in match_asn):
            return RovResult("valid", "", [v for v in match_asn if n.prefixlen <= v.max_length])
        if match_asn:
            return RovResult("invalid", "invalid-length", covering)
        return RovResult("invalid", "invalid-asn", covering)

    # ------------------------------------------------------------------ io
    @classmethod
    def load(cls, path: Path) -> "RpkiValidator":
        d = json.loads(path.read_text(encoding="utf-8"))
        return cls([Vrp(r["asn"], r["prefix"], r["maxLength"], r["ta"]) for r in d["roas"]], d.get("meta"))

    @classmethod
    def empty(cls) -> "RpkiValidator":
        return cls([], {"source": None})


def _overlap_filter(covering: list[str]):
    inside: PrefixIndex[bool] = PrefixIndex()
    supernets: set[str] = set()
    for c in covering:
        n = net(c)
        inside.add(n, True)
        for plen in range(0, n.prefixlen + 1):
            supernets.add(str(n.supernet(new_prefix=plen)))

    def keep(prefix: str) -> bool:
        return prefix in supernets or bool(inside.covering(prefix))
    return keep


def refresh_vrps(urls: list[str], covering: list[str], out: Path, user_agent: str, log=print,
                 min_total: int = 100000) -> dict:
    """Stream the VRP JSON, keep ROAs that overlap watched space, write a small cache file."""
    keep = _overlap_filter(covering)
    last_err = None
    for url in urls:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": user_agent, "Accept-Encoding": "gzip"})
            with urllib.request.urlopen(req, timeout=300) as r:
                raw = gzip.GzipFile(fileobj=r) if r.headers.get("Content-Encoding") == "gzip" else r
                text = io.TextIOWrapper(raw, encoding="utf-8")
                buildtime, total, kept = None, 0, []
                for line in text:
                    if buildtime is None:
                        m = BUILD_RE.search(line)
                        if m:
                            buildtime = m.group(1)
                    m = ROA_RE.search(line)
                    if not m:
                        continue
                    total += 1
                    if keep(m.group(2)):
                        kept.append({"asn": int(m.group(1)), "prefix": m.group(2),
                                     "maxLength": int(m.group(3)), "ta": m.group(4)})
            if total < min_total:  # sanity check: the global set has ~1M VRPs
                raise ValueError(f"only {total} ROAs parsed from {url}; refusing a partial set")
            meta = {"source": url, "buildtime": buildtime, "global_vrps": total, "kept": len(kept)}
            tmp = out.with_suffix(".tmp")
            tmp.write_text(json.dumps({"meta": meta, "roas": kept}), encoding="utf-8")
            tmp.replace(out)
            log(f"  RPKI: {total} VRPs from {url} (built {buildtime}); kept {len(kept)} overlapping watched space")
            return meta
        except Exception as e:  # try the fallback
            last_err = e
            log(f"  RPKI source {url} failed: {e}")
    raise RuntimeError(f"all VRP sources failed: {last_err}")
