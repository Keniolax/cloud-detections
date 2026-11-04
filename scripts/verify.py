#!/usr/bin/env python3
"""Verify that every technique was detected from CloudTrail.

Reads evidence/detections.json (written by collect.py) and asserts that each
technique's Athena detection returned at least one CloudTrail event. Exits
non-zero and names the missed technique(s) otherwise. This is the week's gate:
it passes only if every detection fired on its own technique.

Wazuh coverage is reported and, when a Wazuh alerts file was collected
(--require-wazuh), also gated.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
EVID = ROOT / "evidence"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--require-wazuh", action="store_true",
                    help="also fail if a technique has no matching Wazuh alert")
    ap.add_argument("--input", default=str(EVID / "detections.json"),
                    help="detections summary to verify")
    args = ap.parse_args()

    summary = json.loads(pathlib.Path(args.input).read_text())
    techniques = summary["techniques"]

    missed_athena = []
    missed_wazuh = []
    for t in techniques:
        athena = t["athena_detected"]
        wz = t["wazuh_alert"] is not None
        mark = "OK " if athena else "MISS"
        wtag = "wazuh:yes" if wz else "wazuh:no"
        ev = t["cloudtrail_event"] or {}
        print(f"[{mark}] {t['key']:<38} {t['mitre']:<11} "
              f"athena_rows={t['athena_rows']} {wtag} "
              f"event={ev.get('eventid','-')}")
        if not athena:
            missed_athena.append(f"{t['key']} ({t['mitre']})")
        if args.require_wazuh and not wz:
            missed_wazuh.append(f"{t['key']} (rule {t['wazuh_id']})")

    ok = True
    if missed_athena:
        print(f"\nFAIL: {len(missed_athena)} technique(s) not detected from "
              f"CloudTrail: {', '.join(missed_athena)}", file=sys.stderr)
        ok = False
    if missed_wazuh:
        print(f"\nFAIL: {len(missed_wazuh)} technique(s) with no Wazuh alert: "
              f"{', '.join(missed_wazuh)}", file=sys.stderr)
        ok = False

    if ok:
        print(f"\nPASS: all {len(techniques)} techniques detected from CloudTrail.")
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
