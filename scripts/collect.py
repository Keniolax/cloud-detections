#!/usr/bin/env python3
"""Collect the CloudTrail detection evidence for each technique.

For every technique it runs the matching Athena SQL over the attack window and
saves the result rows and the first matching CloudTrail event id and time. If a
Wazuh alerts file is given (scripts/wazuh_collect.sh writes one), it attaches
the matching Wazuh alert and its rule id too.

Writes:
  evidence/athena/<key>.json     the detection's result rows
  evidence/detections.json       the per-technique summary verify.py reads
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import pathlib
import subprocess
import sys

import yaml

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import athena_lib  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent
EVID = ROOT / "evidence"


def tf_output(name: str) -> str:
    p = subprocess.run(["terraform", "output", "-raw", name],
                       cwd=ROOT, capture_output=True, text=True)
    if p.returncode != 0:
        raise RuntimeError(f"terraform output {name}: {p.stderr.strip()}")
    return p.stdout.strip()


def parse(ts: str) -> dt.datetime:
    return dt.datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--wazuh-alerts", help="JSON file of Wazuh alerts, if ingested")
    ap.add_argument("--out", default=str(EVID / "detections.json"),
                    help="where to write the summary")
    ap.add_argument("--start", help="override window start (YYYY-MM-DDTHH:MM:SSZ)")
    ap.add_argument("--end", help="override window end")
    ap.add_argument("--disable", default="",
                    help="comma-separated technique keys to treat as disabled "
                         "(their query is skipped, so they count as not detected)")
    args = ap.parse_args()

    disabled = {k for k in args.disable.split(",") if k}
    techniques = yaml.safe_load((ROOT / "techniques.yaml").read_text())
    det = json.loads((EVID / "detonations.json").read_text())

    if args.start and args.end:
        start_dt = parse(args.start)
        end_dt = parse(args.end)
    else:
        start_dt = parse(det["global_start"]) - dt.timedelta(seconds=120)
        end_dt = parse(det["global_end"]) + dt.timedelta(seconds=120)
    start = start_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    end = end_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    start_date = start_dt.strftime("%Y/%m/%d")
    end_date = end_dt.strftime("%Y/%m/%d")

    workgroup = tf_output("athena_workgroup")
    database = tf_output("athena_database")

    wazuh_alerts = []
    if args.wazuh_alerts and pathlib.Path(args.wazuh_alerts).exists():
        for line in pathlib.Path(args.wazuh_alerts).read_text().splitlines():
            line = line.strip()
            if line:
                try:
                    wazuh_alerts.append(json.loads(line))
                except json.JSONDecodeError:
                    pass

    (EVID / "athena").mkdir(parents=True, exist_ok=True)
    summary = {"window": {"start": start, "end": end}, "techniques": []}

    for t in techniques:
        key = t["key"]
        if key in disabled:
            rows = []  # the detection is switched off for this run
        else:
            sql_tpl = (ROOT / "athena" / t["athena"]).read_text()
            sql = athena_lib.substitute(sql_tpl, db=database, start_date=start_date,
                                        end_date=end_date, start=start, end=end)
            rows = athena_lib.run_query(sql, workgroup, database)
            (EVID / "athena" / f"{key}.json").write_text(json.dumps(rows, indent=2) + "\n")

        event = None
        if rows:
            event = {"eventid": rows[0].get("eventid"),
                     "eventtime": rows[0].get("eventtime"),
                     "eventname": rows[0].get("eventname")}

        # Match a Wazuh alert by this technique's rule id.
        wz = None
        rid = str(t["wazuh_id"])
        for a in wazuh_alerts:
            if str(a.get("rule", {}).get("id")) == rid:
                wz = {"rule_id": rid,
                      "level": a.get("rule", {}).get("level"),
                      "description": a.get("rule", {}).get("description"),
                      "eventname": a.get("data", {}).get("aws", {}).get("eventName"),
                      "alert_time": a.get("timestamp")}
                break

        summary["techniques"].append({
            "key": key,
            "stratus": t["stratus"],
            "mitre": t["mitre"],
            "wazuh_id": t["wazuh_id"],
            "athena_detected": bool(rows),
            "athena_rows": len(rows),
            "cloudtrail_event": event,
            "wazuh_alert": wz,
        })
        state = "DETECTED" if rows else "no rows"
        print(f"[collect] {key}: {state} ({len(rows)} rows)"
              + (f", wazuh rule {rid}" if wz else ""), flush=True)

    pathlib.Path(args.out).write_text(json.dumps(summary, indent=2) + "\n")
    print(f"[collect] wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
