# Independent review (critique pass) and what was done about it

Before release, the code was reviewed by three independent reviewers (Claude sub-agents with no
access to the author's reasoning, only to the code), each from one angle: requirements, BGP
architecture, and code quality/security. They could read files and run offline commands but not
edit anything. Their findings were then checked against the code and fixed or explicitly declined.

| Reviewer | Score (before fixes) | Headline finding |
|---|---|---|
| Requirements validator | 7.5 / 10 | Solid and honest; no tests on recorded real data yet, real-replay sample not committed |
| Solution architect (BGP) | 6.5 / 10 | Good design, but several detection-lifecycle bugs undermined "tracks an incident until it ends" |
| Code quality and security | 6.5 / 10 | No exploitable XSS/SQLi found; one bad message could stop the live monitor |

## Fixed (each has a regression test unless noted)

| # | Finding | Fix |
|---|---|---|
| 1 | **A stable hijack auto-resolved after 30 min** (a stable route sends no more UPDATEs, and the quiet timer ignored routes still in the RIB) | Incidents with routes still carrying the anomaly stay open; the quiet timer applies only when nothing is active, or to info/low incidents that have become the new normal |
| 2 | **One malformed RIS message or callback error stopped the live run** | `run_live` and `Monitor.handle` count and skip bad messages and failing callbacks; tested with a fake server sending garbage |
| 3 | `AlertEngine.peer_down` never cleared evidence (peer keys contain `\|`, the split was wrong) | Strip the peer suffix by length |
| 4 | **Forged-origin sub-prefix hijack by a RIS peer** (`666 4788`) was reported only as *info* | New-upstream check now includes the RIS peer's own claimed adjacency |
| 5 | Visibility alarm could stay open forever after a collector restart (too few peers left to evaluate) | The alarm clears when the baseline peer count falls below the minimum |
| 6 | AS_SET handling inconsistent (fake adjacencies across a set; `{X}` origin treated as RPKI-valid) | Adjacency checks skip paths with AS_SETs; RPKI uses NONE for any AS_SET origin (RFC 6811) |
| 7 | Clique-sandwich flagged Tier-1 sibling ASNs (e.g. Lumen AS3549 between AS1299 and AS3356) | 762 sibling ASNs of the 18 clique members are loaded from CAIDA AS-to-org and excluded |
| 8 | AS-path poisoning (`3356 4788 174 4788`) raised false new-upstream alerts | Poisoned paths skip adjacency checks |
| 9 | A rate-limited critical alert could be lost for push channels | Critical always pushes; other rate-limited alerts are retried when budget returns |
| 10 | Live mode mixed PC wall-clock time into the event-time engine (a fast PC clock shortened confirmation windows) | Idle ticks use wall time corrected by the measured offset to RIS timestamps |
| 11 | Duplicate deliveries when a message matched several subscriptions | Message-id de-duplication |
| 12 | Watched ASNs announcing prefixes *outside* the watch list were invisible (prefix-only subscription) | Added `path: "<asn>$"` subscriptions and a new **unexpected origination** detector (the "Malaysian network as culprit" view) |
| 13 | Negative `?limit=` removed the API row cap; some endpoints had no cap | Limits clamped to 1..cap everywhere |
| 14 | Retention (`prune`) never ran; CSV download regenerated every table on disk per request | Hourly pruning in live mode; single-table, in-memory CSV export with a formula-injection guard |
| 15 | `:memory:` databases were per-thread | One shared connection for in-memory stores |
| 16 | One DB error could kill the Telegram sender thread; VRP refresh left stale metadata and wrote non-atomically | Guarded; metadata updated; tmp-file + rename |
| 17 | Prometheus label values unescaped; no DNS-rebinding guard | Labels escaped; requests must be addressed to localhost |
| 18 | Some server values inserted into HTML unescaped (ints/enums, not exploitable) | Escaped anyway |
| 19 | Run logs (containing local Windows paths) were not git-ignored | `data/*.log` ignored |
| 20 | Accuracy totals read like 65 independent incidents | Report now says 13 detections × 5 noise seeds, same author wrote scenarios and detectors |
| 21 | CI silently skipped the recorded-sample replay if the sample was missing | CI now fails without it; a real recorded sample is committed with a test |

## Reviewed and declined, or left as known limitations

| Finding | Decision |
|---|---|
| No resync after a websocket reconnect or for the 3–4 h between the RIPEstat snapshot and live start | **Known limitation, documented.** Re-pulling `bgp-state` would re-apply a snapshot that is itself hours old over fresher live data. The cross-check against RIPEstat measures how much this matters in practice |
| Peers that die without a RIS_PEER_STATE message keep counting as "present" | Known limitation, documented |
| No allow-list for DDoS-scrubbing origins (e.g. a mitigation provider announcing a customer's prefix) | Left as configuration work: scrubbing announcements usually carry a valid ROA, which already drops the severity to *low* |
| Regex parsing of the VRP JSON | Kept: it streams a ~108 MB file in constant memory. Verified that both sources (rpki-client and Cloudflare) use the same one-ROA-per-line format |
| Long functions (`web.do_GET`, `synthetic.build`, `explain`) | Refactoring deferred; covered by tests |
| Compare against BGPalerter on the same prefixes | Good next step for validation (needs Node.js); not done |

## Measured after fixes

* `pytest`: all tests pass (see CI).
* Synthetic accuracy: 13/13 expected detections on each of 5 noise seeds, 0 false alerts (`docs/ACCURACY.md`).
* Live behaviour after fixes: see `docs/LIVE_RUN.md`.
