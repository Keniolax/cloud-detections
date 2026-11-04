#!/usr/bin/env python3
"""Detonate each technique with Stratus Red Team and record UTC times.

Reads techniques.yaml, runs `stratus detonate` for each technique (which warms
up its prerequisites first), and writes evidence/detonations.json with the
start and end time of each detonation and a global attack window. Stratus is
used exactly as its documentation describes: warmup, detonate, and (by
scripts/cleanup.py) cleanup.
"""
from __future__ import annotations

import datetime as dt
import json
import pathlib
import subprocess
import sys

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
EVID = ROOT / "evidence"


import re

AKIA = re.compile(r"A(KIA|SIA)[A-Z0-9]{16}")
SECRET_LINE = re.compile(r"(secret[\w-]*\s*=\s*)\S+", re.IGNORECASE)


def redact(text: str) -> str:
    """Strip access key ids and any 'secret = value' pairs Stratus prints, so
    the committed evidence never carries a credential (even a throwaway one)."""
    text = AKIA.sub("AKIA_REDACTED", text)
    text = SECRET_LINE.sub(r"\1<redacted>", text)
    return text


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def run(cmd: list[str]) -> tuple[int, str]:
    p = subprocess.run(cmd, capture_output=True, text=True)
    return p.returncode, (p.stdout + p.stderr)


def main() -> int:
    techniques = yaml.safe_load((ROOT / "techniques.yaml").read_text())
    EVID.mkdir(exist_ok=True)

    global_start = now()
    records = []
    for t in techniques:
        tid = t["stratus"]
        print(f"[detonate] {tid} ...", flush=True)
        t_start = now()
        code, out = run(["stratus", "detonate", tid])
        t_end = now()
        ok = code == 0
        tail = redact("\n".join(out.strip().splitlines()[-4:]))
        print(f"  -> {'OK' if ok else 'FAILED'} ({t_start}..{t_end})", flush=True)
        if not ok:
            print(f"  stratus output:\n{out}", flush=True)
        records.append({
            "key": t["key"],
            "stratus": tid,
            "mitre": t["mitre"],
            "start": t_start,
            "end": t_end,
            "ok": ok,
            "output_tail": tail,
        })
    global_end = now()

    doc = {
        "global_start": global_start,
        "global_end": global_end,
        "detonations": records,
    }
    (EVID / "detonations.json").write_text(json.dumps(doc, indent=2) + "\n")
    print(f"\n[detonate] wrote {EVID / 'detonations.json'}")
    failed = [r["key"] for r in records if not r["ok"]]
    if failed:
        print(f"[detonate] FAILED: {failed}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
