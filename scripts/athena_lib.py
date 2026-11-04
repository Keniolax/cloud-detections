#!/usr/bin/env python3
"""Run an Athena query through the AWS CLI and return the result rows.

Kept CLI-based (not boto3) so the lab needs only the AWS CLI the week already
installs. The query runs in the lab's workgroup, which enforces the
bytes-scanned cap.
"""
from __future__ import annotations

import json
import subprocess
import time


def _cli(args: list[str]) -> dict:
    p = subprocess.run(["aws"] + args, capture_output=True, text=True)
    if p.returncode != 0:
        raise RuntimeError(f"aws {' '.join(args)} failed: {p.stderr.strip()}")
    return json.loads(p.stdout) if p.stdout.strip() else {}


def run_query(sql: str, workgroup: str, database: str, region: str = "us-east-1",
              timeout_s: int = 120) -> list[dict]:
    start = _cli([
        "athena", "start-query-execution", "--region", region,
        "--work-group", workgroup,
        "--query-execution-context", f"Database={database}",
        "--query-string", sql,
    ])
    qid = start["QueryExecutionId"]

    deadline = time.time() + timeout_s
    while True:
        info = _cli(["athena", "get-query-execution", "--region", region,
                     "--query-execution-id", qid])
        state = info["QueryExecution"]["Status"]["State"]
        if state in ("SUCCEEDED", "FAILED", "CANCELLED"):
            break
        if time.time() > deadline:
            raise TimeoutError(f"Athena query {qid} still {state} after {timeout_s}s")
        time.sleep(2)

    if state != "SUCCEEDED":
        reason = info["QueryExecution"]["Status"].get("StateChangeReason", "")
        raise RuntimeError(f"Athena query {qid} {state}: {reason}")

    results = _cli(["athena", "get-query-results", "--region", region,
                    "--query-execution-id", qid])
    rows = results["ResultSet"]["Rows"]
    if not rows:
        return []
    header = [c.get("VarCharValue", "") for c in rows[0]["Data"]]
    out = []
    for r in rows[1:]:
        vals = [c.get("VarCharValue", None) for c in r["Data"]]
        out.append(dict(zip(header, vals)))
    return out


def substitute(template: str, **kw) -> str:
    sql = template
    for k, v in kw.items():
        sql = sql.replace("${" + k + "}", v)
    return sql
