# Live runs: what BGP Watch actually saw

Two live runs against the real RIPE RIS Live feed on 14 November 2026, watching the six
Malaysian networks in `config/bgpwatch.toml` (937 prefixes, verified at setup; see
[VERIFICATION.md](VERIFICATION.md)). Everything here was measured by the tool or by an outside
source named next to it. Both recordings are committed as offline samples, so every number in
the detection tables can be reproduced with `python -m bgpwatch replay <bundle>`. They are
also pinned by `tests/test_recorded_sample.py`.

## Summary

| | Run 1 | Run 2 |
|---|---|---|
| BGP data received | 01:41 to 02:22 MYT (40.5 min) | 10:24 to 11:22 MYT (58.2 min) |
| RIS Live messages | 1,502 | 2,421 |
| Prefix announcements / withdrawals | 7,467 / 28 | 10,841 / 475 |
| Connection | 1 connect, 0 drops, 0 gaps, 0 malformed frames | 1 connect, 0 drops, 0 gaps, 0 malformed frames |
| RPKI checks (valid / not-found / invalid) | 6,878 / 589 / 0 | 9,890 / 950 / **1** |
| Incidents opened | 9 (all low) | 16 (1 medium, 10 low, 5 info) |
| Notifications (paged) | 0 | **1** |
| Watched prefixes below 60 % visibility | 0 | 0 |
| Offline sample | `data/samples/ris-live-2026-11-14` | `data/samples/ris-live-2026-11-14-run2` |

## What was found

### 1. A real RPKI-invalid route from TM (run 2, the one notification)

At 10:46:19 MYT a RIS peer at rrc23 (Singapore, AS133210) announced **`2401:b000:0:3::/64`
from AS18206** (a TM sibling ASN) with path `133210 56308 7473 4788 18206`. Every ROA covering
that space (AS17971 and AS18206, `2401:b000::/32` maxLength 32 and `2401:b000::/48` maxLength
48, APNIC) allows nothing longer than a /48. Under RFC 6811 a /64 is therefore **Invalid
(length)**. BGP Watch raised `rpki_invalid` at high severity. Because only one peer carried it,
the alert engine lowered it to medium and paged once the 60 s confirmation window had passed
(10:47:20).

**Outside check.** RIPEstat `rpki-validation` (run by Routinator, a different validator from
the rpki-client VRP set BGP Watch uses) returned `invalid_length` for AS18206 +
`2401:b000:0:3::/64`, with the same four ROAs, at 03:27 UTC the same day.

**What the tool got wrong.** The dashboard called it a *new* more-specific. It is not new:
RIPEstat `looking-glass` at 03:27 UTC showed the same /64 held by **5 RIS peers** (rrc01, rrc23
×2 and rrc25 ×2), the oldest with a `last_updated` of 2026-10-27. BGP Watch's baseline only
seeds per-peer routes for prefixes that RIPEstat `announced-prefixes` and `routing-status`
list. A /64 seen by about 5 of roughly 760 peers falls below their visibility cut-off, so BGP
Watch only learned of it when one peer re-announced it during the run. The low visibility fits
the RPKI result: networks that enforce ROV drop the route. So this is a **true positive for
RPKI** and a **false "new" label**. Fixing that (running an RPKI audit of low-visibility
more-specifics at setup) is listed as future work, not done.

### 2. Imperva/Incapsula announcing customer prefixes inside Malaysian space (both runs)

In both runs, AS19551 (RIPEstat holder: `INCAPSULA - Incapsula Inc`, a DDoS-protection
service) originated prefixes inside Maxis, TIME and TM address space through transit networks
that had not appeared in the baseline (AS1299, AS2914, AS4637, AS7473, AS9930). This is
expected behaviour for a scrubbing provider protecting its customers, not a hijack. BGP Watch
rated it **low** (recorded on the dashboard, nobody paged), which is the right call. A network
operator would add AS19551 to an allow-list for their own prefixes.

### 3. New upstreams that are RIS peers (both runs)

Paths where a RIS collector peer sits directly next to AS4788 (for example AS34927, AS37721)
appear and disappear as those peers' sessions flap. Run 1 still rated these low. After that
run the detector was changed to treat a new adjacency to a RIS peer on an already-known prefix
as **info**, so run 2 shows them as info. The forged-origin case on a new more-specific stays
at medium.

Nothing else happened. No watched prefix lost visibility, and there were no origin changes,
MOAS conflicts or route-leak patterns in either window. Two quiet hours are a small sample, so
this shows the tool **does not cry wolf on real traffic**. It does not show that it catches
real hijacks. That is what the labelled synthetic set measures (see [ACCURACY.md](ACCURACY.md)).

## Outside checks on the data itself

| Check | Judge | Result |
|---|---|---|
| Is our per-peer routing table right? (run 2, 60 random watched prefixes) | RIPEstat `looking-glass` (real-time RIS) | Before streaming: identical peer sets 86.7 %, within 2 peers 100 %, AS-path agreement 99.95 %. After 58 min of live updates: 86.7 % / 100 % / **99.93 %** (10 peer routes only in ours, 1 only in RIPEstat). |
| Did RIS Live deliver everything RIPE archived? (run 1, 20 prefixes) | RIPEstat `bgp-updates` (RIS MRT archive) | 315 archived updates, 289 received live. **91.7 %** of archived updates were received; **100 %** of received updates are in the archive. Re-checked 15 h later with fresh archive data: identical. |

The 26 missed updates in the ingest check were all rrc25 announcements, arriving in pairs about
every 5 minutes. That looks like a feed-side pattern (RIS Live not streaming some rrc25
updates), not a client bug: there were 0 gaps, 0 duplicates and 0 malformed frames. It was not
investigated further. Run 2's ingest check could not be done yet, because the RIS archive had
no updates for that window when it was tried shortly after the run. The tool now refuses to
save such a result, and no longer caches early archive replies.

## Problems found during the live runs (and fixed)

* **The PC went to sleep during run 1.** The process ran for 514 min, but BGP data covers only
  40.5 min. The report now shows the real data span next to the process time. Run 2 was made
  with the PC kept awake.
* **The first RIB cross-check was wrong.** It compared per-ASN `bgp-state` results that
  overwrote each other and reported nonsense such as "336 vs 3" peers. It was replaced by the
  per-prefix looking-glass judge above.
* **The quiet-incident counter counted ticks, not incidents.** Run 2 showed 643 for 16
  incidents. Fixed: incidents are now counted once, the report reads the count from the
  database, and there is a regression test in `tests/test_alerts.py`.
* **The dashboard said "LIVE · RIS Live connected" after the run had stopped.** When serving a
  stored database, it now says "LIVE RUN ENDED" and gives the stop time. Open incidents show
  "open when the run ended".

## Limits

RIS sees what a few hundred peer networks see, so events inside Malaysia that never reach
those peers are invisible. Baselines come from RIPEstat snapshots a few hours old. The
route-leak checks depend on CAIDA's inferred relationships. Two live hours on two quiet
windows prove the pipeline works on real data. They do not measure detection recall on real
incidents.

---

# Appendix: generated run reports

Produced by `python -m bgpwatch report --db <run db>`. The run databases are not committed.
Replaying the committed samples with the current code reproduces the same message,
announcement, RPKI and incident counts. The one difference is in run 1: four AS4788 RIS-peer
adjacency incidents now come out as **info** instead of low, because of the detector change
described in "What was found", point 3.

## Live run 1

Generated by `python -m bgpwatch report` from the monitoring database. Every number below was measured by the tool; nothing is estimated.

### Run

* Mode: **live**. Started 2026-11-14 01:41 MYT, process ran 514 min.
* BGP data actually received: 2026-11-14 01:41 MYT to 2026-11-14 02:21 MYT (**40.5 min**). If this is much shorter than the process time, the PC was asleep or offline for the rest.
* Baseline built 2026-11-13T17:41:07Z from RIPEstat RIS snapshot ['2026-11-13T13:59:52'].
* RPKI VRP set: 1035005 VRPs built 2026-11-14T02:10:12Z (https://console.rpki-client.org/vrps.json).
* Connection: 1 connect(s), 0 disconnect(s), 0.0 s total gap; 0 duplicate deliveries dropped, 0 malformed frames, 0 processing errors.
* PC clock vs RIS timestamps: +5.0 s (corrected for).

### Traffic

* RIS Live messages processed: **1,502** (7,467 prefix announcements, 28 withdrawals; 0 RIS peer-down events; 0 malformed messages skipped).
* RPKI checks on announcements: valid 6,878, not-found 589, invalid 0.

| Network | Updates stored | Announcements | Withdrawals | Prefixes with baseline | Avg visibility | Lowest | Degraded (< 60 %) |
|---|---|---|---|---|---|---|---|
| CELCOMDIGI | 184 | 170 | 14 | 27 | 100.0 % | 100 % | 0 |
| MAXIS | 203 | 203 | 0 | 99 | 100.0 % | 100 % | 0 |
| MYREN | 83 | 83 | 0 | 29 | 100.0 % | 100 % | 0 |
| TIME | 1,984 | 1,984 | 0 | 80 | 100.0 % | 100 % | 0 |
| TM | 4,970 | 4,958 | 12 | 638 | 100.0 % | 100 % | 0 |
| UMOBILE | 71 | 69 | 2 | 63 | 100.0 % | 100 % | 0 |

### Detections

* Raw findings: 156 → incidents opened: **9** (reopened silently 7) → notifications: **0**.
* Findings folded into existing incidents: 140; incidents recorded on the dashboard without a notification (below the paging threshold): 9.

| Incident kind | Severity | Count |
|---|---|---|
| new_upstream | low | 9 |

| # | First seen | Network | Kind | Severity | Status | Peers | Summary |
|---|---|---|---|---|---|---|---|
| 2 | 2026-11-14 01:43 MYT | TM | new_upstream | low | resolved | 1 | TM (Telekom Malaysia): AS4788 seen through new upstream AS34927 |
| 1 | 2026-11-14 01:43 MYT | TM | new_upstream | low | resolved | 1 | TM (Telekom Malaysia): AS4788 seen through new upstream AS37721 |
| 3 | 2026-11-14 01:45 MYT | TM | new_upstream | low | resolved | 2 | TM (Telekom Malaysia): AS4788 seen through new upstream AS9583 |
| 4 | 2026-11-14 01:52 MYT | MAXIS | new_upstream | low | open | 2 | Maxis: AS19551 seen through new upstream AS1299 |
| 5 | 2026-11-14 01:52 MYT | TIME | new_upstream | low | open | 2 | TIME dotCom: AS19551 seen through new upstream AS1299 |
| 6 | 2026-11-14 01:52 MYT | TM | new_upstream | low | open | 2 | TM (Telekom Malaysia): AS19551 seen through new upstream AS1299 |
| 7 | 2026-11-14 02:18 MYT | TM | new_upstream | low | resolved | 1 | TM (Telekom Malaysia): AS4788 seen through new upstream AS34927 |
| 8 | 2026-11-14 02:18 MYT | TM | new_upstream | low | resolved | 1 | TM (Telekom Malaysia): AS4788 seen through new upstream AS37721 |
| 9 | 2026-11-14 02:19 MYT | TIME | new_upstream | low | resolved | 1 | TIME dotCom: AS9930 seen through new upstream AS37282 |

## Live run 2

Generated by `python -m bgpwatch report` from the monitoring database. Every number below was measured by the tool; nothing is estimated.

### Run

* Mode: **live**. Started 2026-11-14 10:23 MYT, process ran 61 min.
* BGP data actually received: 2026-11-14 10:24 MYT to 2026-11-14 11:22 MYT (**58.2 min**). If this is much shorter than the process time, the PC was asleep or offline for the rest.
* Baseline built 2026-11-14T02:22:45Z from RIPEstat RIS snapshot ['2026-11-13T23:59:53'].
* RPKI VRP set: 1035009 VRPs built 2026-11-14T02:20:38Z (https://console.rpki-client.org/vrps.json).
* Connection: 1 connect(s), 0 disconnect(s), 0.0 s total gap; 0 duplicate deliveries dropped, 0 malformed frames, 0 processing errors.
* PC clock vs RIS timestamps: +5.7 s (corrected for).

### Traffic

* RIS Live messages processed: **2,421** (10,841 prefix announcements, 475 withdrawals; 0 RIS peer-down events; 0 malformed messages skipped).
* RPKI checks on announcements: valid 9,890, not-found 950, invalid 1.

| Network | Updates stored | Announcements | Withdrawals | Prefixes with baseline | Avg visibility | Lowest | Degraded (< 60 %) |
|---|---|---|---|---|---|---|---|
| CELCOMDIGI | 331 | 305 | 26 | 27 | 100.0 % | 100 % | 0 |
| MAXIS | 258 | 228 | 30 | 99 | 100.0 % | 100 % | 0 |
| MYREN | 179 | 163 | 16 | 29 | 100.0 % | 100 % | 0 |
| TIME | 2,926 | 2,905 | 21 | 80 | 100.0 % | 100 % | 0 |
| TM | 7,459 | 7,142 | 317 | 638 | 100.0 % | 100 % | 0 |
| UMOBILE | 163 | 98 | 65 | 63 | 100.0 % | 100 % | 0 |

### Detections

* Raw findings: 160 → incidents opened: **16** (reopened silently 11) → notifications: **1**.
* Findings folded into existing incidents: 133; incidents recorded on the dashboard without a notification (below the paging threshold): 15.

| Incident kind | Severity | Count |
|---|---|---|
| more_specific_own | info | 1 |
| new_upstream | info | 4 |
| new_upstream | low | 10 |
| rpki_invalid | medium | 1 |

| # | First seen | Network | Kind | Severity | Status | Peers | Summary |
|---|---|---|---|---|---|---|---|
| 1 | 2026-11-14 10:25 MYT | TM | new_upstream | low | open | 2 | TM (Telekom Malaysia): AS4788 seen through new upstream AS9583 |
| 4 | 2026-11-14 10:46 MYT | TM | more_specific_own | info | resolved | 1 | TM (Telekom Malaysia): new more-specific 2401:b000:0:3::/64 from its own AS18206 |
| 5 | 2026-11-14 10:46 MYT | TM | rpki_invalid | medium | open | 1 | TM (Telekom Malaysia): own route 2401:b000:0:3::/64 is RPKI-invalid (invalid-length) |
| 2 | 2026-11-14 10:46 MYT | TM | new_upstream | info | resolved | 1 | TM (Telekom Malaysia): AS4788 seen through new upstream AS34927 |
| 3 | 2026-11-14 10:46 MYT | TM | new_upstream | info | resolved | 1 | TM (Telekom Malaysia): AS4788 seen through new upstream AS37721 |
| 6 | 2026-11-14 10:58 MYT | MAXIS | new_upstream | low | resolved | 1 | Maxis: AS19551 seen through new upstream AS2914 |
| 7 | 2026-11-14 10:58 MYT | TM | new_upstream | low | open | 1 | TM (Telekom Malaysia): AS19551 seen through new upstream AS4637 |
| 8 | 2026-11-14 10:58 MYT | TIME | new_upstream | low | open | 1 | TIME dotCom: AS19551 seen through new upstream AS4637 |
| 9 | 2026-11-14 10:58 MYT | MAXIS | new_upstream | low | open | 1 | Maxis: AS19551 seen through new upstream AS4637 |
| 10 | 2026-11-14 10:58 MYT | TIME | new_upstream | low | resolved | 1 | TIME dotCom: AS19551 seen through new upstream AS2914 |
| 11 | 2026-11-14 10:59 MYT | TM | new_upstream | low | open | 1 | TM (Telekom Malaysia): AS19551 seen through new upstream AS9930 |
| 12 | 2026-11-14 11:00 MYT | TIME | new_upstream | low | open | 1 | TIME dotCom: AS19551 seen through new upstream AS1299 |
| 13 | 2026-11-14 11:00 MYT | MAXIS | new_upstream | low | open | 1 | Maxis: AS19551 seen through new upstream AS1299 |
| 14 | 2026-11-14 11:00 MYT | TIME | new_upstream | low | open | 1 | TIME dotCom: AS19551 seen through new upstream AS7473 |
| 15 | 2026-11-14 11:20 MYT | TM | new_upstream | info | resolved | 1 | TM (Telekom Malaysia): AS4788 seen through new upstream AS34927 |
| 16 | 2026-11-14 11:20 MYT | TM | new_upstream | info | resolved | 1 | TM (Telekom Malaysia): AS4788 seen through new upstream AS37721 |

### Outside check: our per-peer RIB vs RIPEstat looking-glass

RIPEstat `looking-glass` shows the route every RIS peer holds right now. For a fixed random sample of watched prefixes, BGP Watch's per-peer table was compared with it before streaming started (accuracy of the RIPEstat `bgp-state` seed, which is a few hours old) and again at the end (after live updates).

| Check | Prefixes | Identical peer sets | Within 2 peers / 2 % | AS-path agreement (common peers) | Peer routes only in ours | Only in RIPEstat | Looking-glass data time (UTC) |
|---|---|---|---|---|---|---|---|
| Before streaming (seed) | 60 | 86.7 % | 100.0 % | 99.95 % | 10 | 1 | 2026-11-14T02:22:59 to 2026-11-14T02:24:02 |
| After the live run | 60 | 86.7 % | 100.0 % | 99.93 % | 10 | 1 | 2026-11-14T03:23:45 to 2026-11-14T03:26:22 |

Largest differences at the end (prefix, peers ours / RIPEstat, peer-set difference, path mismatches):

* `2401:3c00:250::/47`: 357 / 355, diff 2, path mismatches 0
* `2401:3c00:22c::/47`: 358 / 356, diff 2, path mismatches 0
* `2401:3c00:21c::/48`: 356 / 354, diff 2, path mismatches 0
* `2400:7400:e028::/48`: 327 / 326, diff 1, path mismatches 0
* `2001:d08:da::/47`: 329 / 328, diff 1, path mismatches 0
* `103.9.148.0/24`: 379 / 380, diff 1, path mismatches 0
* `2400:7400:e025::/48`: 327 / 326, diff 1, path mismatches 0
* `2404:160::/32`: 355 / 354, diff 1, path mismatches 0

