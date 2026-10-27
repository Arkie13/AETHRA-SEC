"""Reconcile generated test runs against AETHRA-SEC's recorded detections.

Reads the attacker's run_log.csv (produced by
evaluation/lab_testing/aethra_detection_test.sh), matches each generated run
to the AETHRA-SEC detection episode(s) it caused, and writes a per-run status
table. This is how 100 generated runs become 100 auditable test executions:
each row of run_log.csv is one planned/started/completed execution with a
distinct Run ID, and this tool records what was actually detected for it -
never inferring success from the fact that the generator ran.

It is READ-ONLY on the database (SELECT only). It writes a CSV and a small
JSON summary; it does not touch traffic_anomalies, snort_alerts or any
research data, and it inserts nothing.

Run ID: scenario + run number from the log (e.g. ICMP-0007), which is unique
per scenario even when the attack type, source, destination and signature
repeat. The log's own start/stop timestamps are the audit trail.

Status per run (honest; never a fabricated pass):
  DETECTED            - a matching AETHRA-SEC episode overlaps the run window.
  DETECTED_SNORT_ONLY - only a Snort alert matched; AETHRA-SEC raised nothing.
  MISSED              - the run completed but nothing matched it.
  NO_END_TIME         - the log has no stop time (crash/interruption); partial.
  AMBIGUOUS           - more than one run could own the same episode.
  NOT_TESTED          - a planned row with no start time.

Usage (on the AETHRA-SEC machine, after a test batch):
  python scripts/reconcile_test_runs.py --log <path-to>/run_log.csv \
      [--out <dir>] [--window 8] [--target 192.168.1.26]

Timestamps: run_log.csv is UTC (the harness writes `date -u`). AETHRA-SEC
stores UTC. Both are compared as UTC; no cross-clock subtraction is done
beyond matching a run's [start, end] window (widened by --window seconds for
capture/analysis lag) against an episode's [first_seen, last_seen].
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aethra_sec.analytics.attack_categories import (  # noqa: E402
    AETHRA_RULE_CATEGORY,
)
from aethra_sec.config.settings import load_settings  # noqa: E402
from aethra_sec.database.connection import DatabaseManager  # noqa: E402

#: run_log.csv scenario -> the AETHRA-SEC category the harness exercises.
SCENARIO_CATEGORY = {
    "ICMP": "ICMP", "UDP": "UDP", "SYN": "TCP", "HTTP": "HTTP",
    "PORTSCAN": "PORT SCAN",
}
#: AETHRA-SEC rule -> category, inverted for matching.
CATEGORY_RULES: dict[str, list[str]] = {}
for _rule, _cat in AETHRA_RULE_CATEGORY.items():
    CATEGORY_RULES.setdefault(_cat, []).append(_rule)


def _parse_utc(text: str) -> datetime | None:
    text = (text or "").strip()
    if not text:
        return None
    try:
        return datetime.strptime(text, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def load_runs(log_path: Path) -> list[dict]:
    with log_path.open(encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def episodes_for(db: DatabaseManager, rules: list[str], start: datetime,
                 end: datetime, target: str | None) -> list[dict]:
    if not rules:
        return []
    placeholders = ",".join(["%s"] * len(rules))
    clauses = [f"rule_id IN ({placeholders})", "last_seen >= %s", "first_seen <= %s"]
    params: list = [*rules, _to_naive(start), _to_naive(end)]
    if target:
        clauses.append("dst_ip = %s")
        params.append(target)
    rows = db.query(
        "SELECT id, rule_id, src_ip, dst_ip, severity, first_seen, last_seen, "
        "observed_value, latest_value, incident_id "
        f"FROM traffic_anomalies WHERE {' AND '.join(clauses)} ORDER BY first_seen",
        params,
    )
    return rows


def snort_for(db: DatabaseManager, start: datetime, end: datetime,
              src: str | None) -> int:
    clauses = ["COALESCE(last_alert_time, alert_time, received_at) >= %s",
               "COALESCE(alert_time, received_at) <= %s"]
    params: list = [_to_naive(start), _to_naive(end)]
    if src:
        clauses.append("src_ip = %s")
        params.append(src)
    row = db.query_one(
        f"SELECT COUNT(*) c FROM snort_alerts WHERE {' AND '.join(clauses)}", params)
    return int(row["c"]) if row else 0


def _to_naive(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")


def reconcile(log_path: Path, out_dir: Path, window: int,
              target: str | None) -> dict:
    runs = load_runs(log_path)
    db = DatabaseManager(load_settings().database)
    widen = timedelta(seconds=max(0, window))
    results: list[dict] = []
    used_episodes: dict[int, str] = {}

    for row in runs:
        scenario = (row.get("scenario") or "").strip().upper()
        run_no = (row.get("run") or "").strip()
        run_id = f"{scenario}-{int(run_no):04d}" if run_no.isdigit() else \
            f"{scenario}-{run_no}"
        start = _parse_utc(row.get("start_utc", ""))
        end = _parse_utc(row.get("end_utc", ""))
        src = None  # the attacker; run_log records the target, not the source
        tgt = target or (row.get("target") or "").strip() or None
        category = SCENARIO_CATEGORY.get(scenario, "")
        rules = CATEGORY_RULES.get(category, [])

        record = {
            "run_id": run_id, "scenario": scenario, "run": run_no,
            "category": category, "target": tgt,
            "start_utc": row.get("start_utc", ""), "end_utc": row.get("end_utc", ""),
            "aethra_episode_ids": "", "aethra_severity": "",
            "snort_alerts": "", "status": "", "note": "",
        }

        if start is None:
            record["status"] = "NOT_TESTED"
            record["note"] = "no start time in the log (planned, not started)"
            results.append(record)
            continue
        partial = end is None
        window_end = (end or start) + widen
        window_start = start - widen

        episodes = episodes_for(db, rules, window_start, window_end, tgt)
        snort = snort_for(db, window_start, window_end, src)
        record["snort_alerts"] = str(snort)

        if episodes:
            ids = [str(e["id"]) for e in episodes]
            record["aethra_episode_ids"] = ";".join(ids)
            record["aethra_severity"] = ";".join(
                sorted({str(e["severity"]) for e in episodes}))
            clash = [i for i in ids if i in used_episodes]
            for i in ids:
                used_episodes.setdefault(i, run_id)
            if clash:
                record["status"] = "AMBIGUOUS"
                record["note"] = (
                    "episode(s) " + ",".join(clash) + " also matched " +
                    ",".join(sorted({used_episodes[i] for i in clash})) +
                    "; widen the run gap or narrow --window")
            elif partial:
                record["status"] = "DETECTED_PARTIAL"
                record["note"] = "no end time (interrupted); detection matched the start"
            else:
                record["status"] = "DETECTED"
        elif partial:
            record["status"] = "NO_END_TIME"
            record["note"] = "run interrupted (no end time) and nothing matched"
        elif snort:
            record["status"] = "DETECTED_SNORT_ONLY"
            record["note"] = "only Snort matched; AETHRA-SEC raised no episode"
        else:
            record["status"] = "MISSED"
            record["note"] = "run completed; no AETHRA-SEC or Snort detection matched"
        results.append(record)

    out_dir.mkdir(parents=True, exist_ok=True)
    csv_path = out_dir / "reconciled_runs.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(results[0].keys())
                                if results else ["run_id"])
        writer.writeheader()
        writer.writerows(results)

    by_scenario: dict[str, dict[str, int]] = {}
    for record in results:
        bucket = by_scenario.setdefault(record["scenario"], {})
        bucket[record["status"]] = bucket.get(record["status"], 0) + 1
    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "log": str(log_path),
        "match_window_seconds": window,
        "total_runs": len(results),
        "by_scenario": by_scenario,
        "note": ("Status is derived from matched detections only. A run is never "
                 "marked DETECTED because the generator started. DETECTED counts "
                 "unique AETHRA-SEC episodes, not packets or raw alerts."),
    }
    json_path = out_dir / "reconciliation_summary.json"
    json_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"Wrote {csv_path}")
    print(f"Wrote {json_path}")
    for scenario, counts in sorted(by_scenario.items()):
        print(f"  {scenario:10s} " +
              " ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", required=True, type=Path,
                        help="run_log.csv from the attack harness")
    parser.add_argument("--out", type=Path,
                        default=Path(__file__).resolve().parent.parent /
                        "evaluation" / "stability_revision" / "EVIDENCE",
                        help="output directory")
    parser.add_argument("--window", type=int, default=8,
                        help="seconds to widen each run window for capture/analysis lag")
    parser.add_argument("--target", default="",
                        help="override the target IP (else the log's target column)")
    args = parser.parse_args(argv)
    if not args.log.is_file():
        print(f"Log not found: {args.log}", file=sys.stderr)
        return 2
    reconcile(args.log, args.out, args.window, args.target or None)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
