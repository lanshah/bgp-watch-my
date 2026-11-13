"""Polite HTTP access to public routing data sources.

* RIPEstat Data API  - rules: no request cap, register above 1000 requests/day,
  max 8 concurrent requests per IP. We use <= 4 concurrent and space requests out.
* PeeringDB API      - anonymous access is rate limited; we make a handful of calls.
* CAIDA AS Rank API  - GraphQL; a handful of calls per baseline build.

Every response is cached on disk (data/cache) so re-running a build does not hit the
APIs again until the cache expires. Requests carry only a generic client name.
"""
from __future__ import annotations

import gzip
import hashlib
import json
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from .config import Config


class SourceError(RuntimeError):
    pass


class HttpClient:
    def __init__(self, cfg: Config, cache_dir: Path | None = None, offline: bool = False):
        self.cfg = cfg
        src = cfg.sources
        self.ua = cfg.user_agent
        self.sourceapp = cfg.client_name
        self.sem = threading.Semaphore(int(src.get("max_concurrent", 4)))
        self.min_interval = float(src.get("min_interval_s", 0.25))
        self.ttl = float(src.get("cache_ttl_h", 12)) * 3600
        self.cache_dir = cache_dir or cfg.data_dir / "cache"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.offline = offline
        self._last = 0.0
        self._lock = threading.Lock()
        self.calls = 0  # real network calls made (for the request budget report)

    # ------------------------------------------------------------------
    def _cache_file(self, key: str) -> Path:
        return self.cache_dir / (hashlib.sha256(key.encode()).hexdigest()[:32] + ".json.gz")

    def _pace(self) -> None:
        with self._lock:
            wait = self._last + self.min_interval - time.monotonic()
            if wait > 0:
                time.sleep(wait)
            self._last = time.monotonic()

    def fetch_json(self, url: str, body: dict | None = None, ttl: float | None = None,
                   timeout: float = 120, retries: int = 3) -> dict:
        key = url + ("|" + json.dumps(body, sort_keys=True) if body else "")
        cf = self._cache_file(key)
        ttl = self.ttl if ttl is None else ttl
        if cf.exists() and (self.offline or time.time() - cf.stat().st_mtime < ttl):
            with gzip.open(cf, "rt", encoding="utf-8") as fh:
                return json.load(fh)
        if self.offline:
            raise SourceError(f"offline and not cached: {url}")
        headers = {"User-Agent": self.ua, "Accept": "application/json"}
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        last_err: Exception | None = None
        for attempt in range(retries):
            with self.sem:
                self._pace()
                try:
                    req = urllib.request.Request(url, data=data, headers=headers)
                    with urllib.request.urlopen(req, timeout=timeout) as r:
                        payload = json.load(r)
                    self.calls += 1
                    break
                except urllib.error.HTTPError as e:  # 429 / 5xx -> back off and retry
                    last_err = e
                    if e.code not in (429, 500, 502, 503, 504):
                        raise SourceError(f"HTTP {e.code} for {url}") from e
                except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as e:
                    last_err = e
            time.sleep(2 ** attempt * 2)
        else:
            raise SourceError(f"failed after {retries} attempts: {url}: {last_err}")
        tmp = cf.with_suffix(".tmp")
        with gzip.open(tmp, "wt", encoding="utf-8") as fh:
            json.dump(payload, fh)
        tmp.replace(cf)
        return payload

    # ---------------------------------------------------------------- RIPEstat
    def ripestat(self, endpoint: str, ttl: float | None = None, **params) -> dict:
        params["sourceapp"] = self.sourceapp
        url = f"{self.cfg.sources['ripestat']}/{endpoint}/data.json?" + urllib.parse.urlencode(params)
        d = self.fetch_json(url, ttl=ttl)
        if d.get("status") != "ok":
            raise SourceError(f"RIPEstat {endpoint} status={d.get('status')} {d.get('messages')}")
        d["data"]["_source_url"] = url
        d["data"]["_fetched"] = d.get("time")
        return d["data"]

    # ---------------------------------------------------------------- PeeringDB
    def peeringdb_net(self, asn: int) -> dict | None:
        url = f"{self.cfg.sources['peeringdb']}/net?asn={asn}"
        d = self.fetch_json(url)
        rows = d.get("data", [])
        if rows:
            rows[0]["_source_url"] = url
        return rows[0] if rows else None

    # ---------------------------------------------------------------- CAIDA AS Rank
    def caida(self, query: str) -> dict:
        d = self.fetch_json(self.cfg.sources["caida_asrank"], body={"query": query}, ttl=7 * 86400)
        if "errors" in d:
            raise SourceError(f"CAIDA AS Rank error: {d['errors']}")
        return d["data"]

    def caida_clique(self) -> dict:
        """The transit-free clique from the latest AS Rank dataset record.

        Note: the per-AS `cliqueMember` flag returned true for every AS we tested (Nov 2026),
        so we use the dataset's own `clique` list instead (18 ASes in the 2026-11-01 dataset)."""
        d = self.caida('{ datasets(first:1, sort:"-date") { edges { node { date clique } } } }')
        node = d["datasets"]["edges"][0]["node"]
        names = {}
        q = "{ asns(asns:[%s], first:100) { edges { node { asn asnName } } } }" % ",".join(
            '"%s"' % a for a in node["clique"])
        for e in self.caida(q)["asns"]["edges"]:
            names[e["node"]["asn"]] = e["node"]["asnName"]
        return {"date": node["date"], "members": [{"asn": int(a), "name": names.get(a, "")} for a in node["clique"]]}

    def caida_siblings(self, asns: list[int]) -> list[int]:
        """All ASNs of the organisations that own `asns` (CAIDA AS-to-org)."""
        q = "{ asns(asns:[%s], first:100) { edges { node { asn organization { orgId } } } } }" % ",".join(
            '"%d"' % a for a in asns)
        orgs = {e["node"]["organization"]["orgId"] for e in self.caida(q)["asns"]["edges"]
                if e["node"].get("organization")}
        out: set[int] = set()
        for org in sorted(orgs):
            d = self.caida('{ organization(orgId:"%s") { members { asns(first:500) { edges { node { asn } } } } } }'
                           % org)
            node = d.get("organization") or {}
            for e in ((node.get("members") or {}).get("asns") or {}).get("edges", []):
                out.add(int(e["node"]["asn"]))
        return sorted(out)

    def caida_links(self, asn: int) -> list[dict]:
        out, offset = [], 0
        for _ in range(20):
            q = ("{ asnLinks(asn:\"%d\", first:500, offset:%d) { pageInfo { hasNextPage } "
                 "edges { node { relationship asn1 { asn asnName } } } } }" % (asn, offset))
            d = self.caida(q)["asnLinks"]
            out += [e["node"] for e in d["edges"]]
            if not d["pageInfo"]["hasNextPage"]:
                break
            offset += 500
        return out
