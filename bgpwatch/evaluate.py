"""Measured accuracy of the detectors on the labelled synthetic incident set.

Scoring rules (fixed before looking at results):
* An expected item is DETECTED if an incident of the same kind and network (and actor AS /
  prefix when the label gives one) first appears inside the scenario window, and its peak
  severity satisfies the label's min/max severity bound.
* A FALSE ALERT is a notified incident (severity >= medium) that matches no expected item.
  Benign scenarios have no expected notified items, so anything that pages during them is false.
* Notifications per expected item are counted to check de-duplication (max_notifications).
"""
from __future__ import annotations

import json
from pathlib import Path

from .config import Config, severity_rank
from .replay import replay_bundle
from .store import Store
from .synthetic import write_bundle


def score(store: Store, labels: list[dict]) -> dict:
    incs = store.query("SELECT * FROM incidents")
    notes = store.query("SELECT incident_id, COUNT(*) AS n FROM notifications WHERE channel='dashboard' "
                        "GROUP BY incident_id")
    nmap = {r["incident_id"]: r["n"] for r in notes}
    peak = {}
    for r in store.query("SELECT incident_id, severity FROM notifications WHERE channel='dashboard'"):
        if severity_rank(r["severity"]) > severity_rank(peak.get(r["incident_id"], "info")):
            peak[r["incident_id"]] = r["severity"]
    for i in incs:
        i["prefixes"] = json.loads(i["prefixes"] or "[]")
        i["peak"] = peak.get(i["id"], i["severity"])
        if severity_rank(i["severity"]) > severity_rank(i["peak"]):
            i["peak"] = i["severity"]
        i["notifications"] = nmap.get(i["id"], 0)
    matched_ids = set()
    rows = []
    det = missed = 0
    for lab in labels:
        for exp in lab["expected"]:
            hit = None
            for i in incs:
                if i["kind"] != exp["kind"] or i["network"] != exp["network"]:
                    continue
                if "actor_asn" in exp and i["actor_asn"] != exp["actor_asn"]:
                    continue
                if "prefix" in exp and exp["prefix"] not in i["prefixes"]:
                    continue
                if not (lab["start"] - 5 <= i["first_seen"] <= lab["end"]):
                    continue
                hit = i
                break
            ok, why = hit is not None, ""
            if hit:
                matched_ids.add(hit["id"])
                if "min_severity" in exp and severity_rank(hit["peak"]) < severity_rank(exp["min_severity"]):
                    ok, why = False, f"severity {hit['peak']} < {exp['min_severity']}"
                if "max_severity" in exp and severity_rank(hit["peak"]) > severity_rank(exp["max_severity"]):
                    ok, why = False, f"severity {hit['peak']} > {exp['max_severity']}"
                if "max_notifications" in exp and hit["notifications"] > exp["max_notifications"]:
                    ok, why = False, f"{hit['notifications']} notifications > {exp['max_notifications']}"
            else:
                why = "no matching incident"
            det += ok
            missed += not ok
            first_note = None
            if hit:
                fn = store.query("SELECT MIN(ts) AS t FROM notifications WHERE incident_id=? AND channel='dashboard'",
                                 (hit["id"],))
                first_note = fn[0]["t"] if fn and fn[0]["t"] else None
            rows.append({"scenario": lab["id"], "name": lab["name"], "kind": exp["kind"], "detected": ok,
                         "incident_id": hit["id"] if hit else None, "peak_severity": hit["peak"] if hit else None,
                         "notifications": hit["notifications"] if hit else 0,
                         "time_to_detect_s": round(hit["first_seen"] - lab["start"], 1) if hit else None,
                         "time_to_notify_s": round(first_note - lab["start"], 1) if first_note else None,
                         "note": why})
    false_alerts = [i for i in incs if i["id"] not in matched_ids and severity_rank(i["peak"]) >= severity_rank("medium")]
    benign = [l for l in labels if l["benign"]]
    benign_paged = []
    for l in benign:
        for i in false_alerts:
            if l["start"] - 5 <= i["first_seen"] <= l["end"]:
                benign_paged.append(l["id"])
    total_notes = sum(i["notifications"] for i in incs)
    return {
        "expected_items": det + missed, "detected": det, "missed": missed,
        "false_alerts": len(false_alerts),
        "false_alert_details": [{"id": i["id"], "kind": i["kind"], "network": i["network"], "title": i["title"],
                                 "severity": i["peak"]} for i in false_alerts],
        "benign_scenarios": len(benign), "benign_scenarios_paged": sorted(set(benign_paged)),
        "incidents": len(incs), "notifications": total_notes,
        "rows": rows,
    }


def evaluate(cfg: Config, out_dir: Path, seeds: list[int], db: Path | None = None, log=print) -> dict:
    runs = []
    for seed in seeds:
        bdir = out_dir / f"seed-{seed}"
        meta = write_bundle(bdir, seed)
        store = Store(db or ":memory:") if len(seeds) == 1 else Store(":memory:")
        mon, res = replay_bundle(cfg, bdir, store, source="synthetic", log=log)
        labels = json.loads((bdir / "labels.json").read_text(encoding="utf-8"))
        sc = score(store, labels)
        sc.update({"seed": seed, "messages": meta["messages"], "engine": mon.engine.stats,
                   "replay_wall_s": res["wall_s"]})
        runs.append(sc)
        log(f"  seed {seed}: detected {sc['detected']}/{sc['expected_items']}, missed {sc['missed']}, "
            f"false alerts {sc['false_alerts']}, notifications {sc['notifications']}, "
            f"{meta['messages']} messages in {res['wall_s']} s")
    agg = {
        "seeds": seeds,
        "expected_items": sum(r["expected_items"] for r in runs),
        "detected": sum(r["detected"] for r in runs),
        "missed": sum(r["missed"] for r in runs),
        "false_alerts": sum(r["false_alerts"] for r in runs),
        "runs": runs,
    }
    return agg


def write_report(agg: dict, path: Path) -> None:
    r0 = agg["runs"][0]
    lines = [
        "# Detector accuracy on the labelled SYNTHETIC incident set",
        "",
        "Generated by `python -m bgpwatch evaluate`. The incident set is fictional (reserved ASNs and prefixes, see",
        "`bgpwatch/synthetic.py`) and was written to exercise each detector, including benign look-alikes",
        "that must **not** page anyone. Scoring rules are in `bgpwatch/evaluate.py` and were fixed before the run.",
        "",
        "These numbers show the detectors behave as designed on cases they were built for. They are **not** a",
        "measure of real-world precision: real BGP has messier edge cases than any scripted set, and the same",
        "person wrote both the scenarios and the detectors.",
        "",
        "**How to read the totals:** the set has 16 scenarios with 13 expected detections (5 scenarios are benign",
        "look-alikes that must stay silent). Each seed replays the *same* scenarios with different random background",
        "churn (path changes, duplicate announcements, short single-peer withdrawals), so 5 seeds = 13 detections x 5",
        "noise runs, not 65 independent incidents.",
        "",
        "**History:** the first run of this check (before any tuning) found 2 false alerts, both real design bugs:",
        "a sibling ASN's announcement counted as lost visibility, and a hijack was double-counted as a visibility drop.",
        "Both were fixed in the detectors (not by changing the labels). A later independent code review found further",
        "logic bugs (e.g. a stable hijack auto-resolving after 30 min, forged-origin sub-prefix rated info); those",
        "fixes have regression tests in `tests/`.",
        "",
        "## Summary over all seeds",
        "",
        "| Seeds | Expected detections | Detected | Missed | False alerts |",
        "|---|---|---|---|---|",
        f"| {', '.join(map(str, agg['seeds']))} | {agg['expected_items']} | {agg['detected']} | {agg['missed']} | {agg['false_alerts']} |",
        "",
        f"## Per scenario (seed {r0['seed']}, {r0['messages']} messages, replayed in {r0['replay_wall_s']} s)",
        "",
        "| Scenario | Expected | Result | Peak severity | Notifications | Time to detect | Note |",
        "|---|---|---|---|---|---|---|",
    ]
    for row in r0["rows"]:
        lines.append(f"| {row['scenario']} {row['name']} | {row['kind']} | {'detected' if row['detected'] else '**MISSED**'} | "
                     f"{row['peak_severity'] or '-'} | {row['notifications']} | "
                     f"{'-' if row['time_to_detect_s'] is None else str(row['time_to_detect_s']) + ' s'} | {row['note']} |")
    lines += ["", "Benign scenarios (must not page): " + ", ".join(
        f"{l}" for l in ["S4", "S7", "S13", "S15", "S16"]) +
        f". Paged during benign scenarios: {', '.join(r0['benign_scenarios_paged']) or 'none'}.", ""]
    if r0["false_alert_details"]:
        lines += ["False alerts:", ""] + [f"* #{f['id']} {f['kind']} {f['network']} {f['severity']}: {f['title']}"
                                          for f in r0["false_alert_details"]] + [""]
    e = r0["engine"]
    lines += ["## Alert-noise reduction (seed %d)" % r0["seed"], "",
              f"* Findings raised by detectors: {e['findings']}",
              f"* Incidents opened: {e['incidents_opened']} (reopened silently: {e['incidents_reopened']})",
              f"* Notifications pushed: {e['notifications']}",
              f"* Findings folded into existing incidents (de-duplicated): {e['dedup_suppressed']}",
              f"* Info/low-severity incidents recorded without paging: {e['low_severity_not_notified']}",
              ""]
    path.write_text("\n".join(lines), encoding="utf-8")
