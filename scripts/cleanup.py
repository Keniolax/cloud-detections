#!/usr/bin/env python3
"""Clean up every Stratus technique and confirm each is COLD.

Runs `stratus cleanup` for each technique in techniques.yaml, then reads
`stratus status` and fails if any technique is not COLD. Nothing may be left
warm before the lab is torn down.
"""
from __future__ import annotations

import pathlib
import subprocess
import sys

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent


def main() -> int:
    techniques = yaml.safe_load((ROOT / "techniques.yaml").read_text())
    ids = [t["stratus"] for t in techniques]

    for tid in ids:
        print(f"[cleanup] {tid}", flush=True)
        subprocess.run(["stratus", "cleanup", tid], text=True)

    status = subprocess.run(["stratus", "status"], capture_output=True, text=True)
    out = status.stdout + status.stderr
    print(out)

    not_cold = []
    for tid in ids:
        for line in out.splitlines():
            if tid in line and "COLD" not in line:
                not_cold.append(tid)
                break
    if not_cold:
        print(f"[cleanup] NOT COLD: {not_cold}", file=sys.stderr)
        return 1
    print("[cleanup] all techniques COLD")
    return 0


if __name__ == "__main__":
    sys.exit(main())
