#!/usr/bin/env python3
"""Export GuardDuty findings for the attack window and compare them with the
CloudTrail detections.

GuardDuty reads the account's logs itself (not our trail) and raises its own
findings on a different, slower clock. This writes:
  evidence/guardduty/findings.json     every real (non-sample) finding
  evidence/guardduty/comparison.json   per technique: caught by our detection,
                                        caught by GuardDuty, and how long each took

Sample findings (service.additionalInfo.sample == true) are left out.
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
REGION = "us-east-1"

# Which GuardDuty finding-type fragments line up with which technique. A
# finding type that matches none of these is still exported, just not mapped.
GD_MAP = {
    "cloudtrail-stop": ["CloudTrailLoggingDisabled", "LoggingConfigurationModified"],
    "cloudtrail-event-selectors": ["LoggingConfigurationModified", "CloudTrailLoggingDisabled"],
    "iam-create-admin-user": ["AdministrativePermissions", "AnomalousBehavior"],
    "iam-backdoor-user": ["AnomalousBehavior"],
    "s3-backdoor-bucket-policy": ["Policy:S3", "BucketAnonymousAccessGranted", "S3"],
    "secretsmanager-batch-retrieve-secrets": ["AnomalousBehavior", "Secrets"],
    "ses-enumerate": ["AnomalousBehavior", "SES"],
}


def cli(args: list[str]) -> dict:
    p = subprocess.run(["aws"] + args, capture_output=True, text=True)
    if p.returncode != 0:
        raise RuntimeError(f"aws {' '.join(args)}: {p.stderr.strip()}")
    return json.loads(p.stdout) if p.stdout.strip() else {}


def parse(ts: str) -> dt.datetime:
    return dt.datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)


def unavailable(reason: str) -> int:
    """GuardDuty is not usable in this account: record that honestly and still
    write a comparison so the week's table has a GuardDuty column."""
    (EVID / "guardduty").mkdir(parents=True, exist_ok=True)
    techniques = yaml.safe_load((ROOT / "techniques.yaml").read_text())
    det = json.loads((EVID / "detections.json").read_text())
    comparison = []
    for t in techniques:
        own = next(x for x in det["techniques"] if x["key"] == t["key"])
        comparison.append({
            "key": t["key"], "mitre": t["mitre"],
            "own_detection": own["athena_detected"],
            "guardduty": None, "guardduty_type": None, "guardduty_latency_s": None,
        })
    (EVID / "guardduty" / "comparison.json").write_text(json.dumps(
        {"detector_id": None, "guardduty_available": False,
         "reason": reason, "real_findings": 0, "comparison": comparison}, indent=2) + "\n")
    (EVID / "guardduty" / "findings.json").write_text("[]\n")
    print(f"[gd] GuardDuty unavailable: {reason}")
    print("[gd] wrote comparison with GuardDuty marked unavailable")
    return 0


def main() -> int:
    detector_id = sys.argv[1] if len(sys.argv) > 1 else None
    if not detector_id:
        try:
            ids = cli(["guardduty", "list-detectors", "--region", REGION]).get("DetectorIds", [])
        except RuntimeError as e:
            return unavailable(str(e).split(":", 2)[-1].strip())
        if not ids:
            return unavailable("no GuardDuty detector in this account")
        detector_id = ids[0]

    (EVID / "guardduty").mkdir(parents=True, exist_ok=True)

    ids = cli(["guardduty", "list-findings", "--region", REGION,
               "--detector-id", detector_id]).get("FindingIds", [])
    findings = []
    if ids:
        # get-findings takes up to 50 ids at a time.
        for i in range(0, len(ids), 50):
            batch = ids[i:i + 50]
            resp = cli(["guardduty", "get-findings", "--region", REGION,
                        "--detector-id", detector_id,
                        "--finding-ids", *batch])
            findings.extend(resp.get("Findings", []))

    real = [f for f in findings
            if not f.get("Service", {}).get("AdditionalInfo", {}).get("Sample", False)]

    slim = [{
        "id": f["Id"],
        "type": f["Type"],
        "severity": f["Severity"],
        "title": f.get("Title", ""),
        "createdAt": f.get("CreatedAt", ""),
        "resource": f.get("Resource", {}).get("ResourceType", ""),
    } for f in real]
    (EVID / "guardduty" / "findings.json").write_text(json.dumps(slim, indent=2) + "\n")

    # Compare with our detections.
    det = json.loads((EVID / "detections.json").read_text())
    detonations = {d["key"]: d for d in
                   json.loads((EVID / "detonations.json").read_text())["detonations"]}
    techniques = yaml.safe_load((ROOT / "techniques.yaml").read_text())

    comparison = []
    for t in techniques:
        key = t["key"]
        own = next(x for x in det["techniques"] if x["key"] == key)
        # our detection latency: event time (not delivery) is the attack time;
        # the detection is available once the log is queryable. We report the
        # CloudTrail event time as the moment the signal existed.
        own_detected = own["athena_detected"]

        # GuardDuty match
        gd_hit = None
        for f in real:
            if any(frag.lower() in f["Type"].lower() for frag in GD_MAP.get(key, [])):
                gd_hit = f
                break
        gd_latency = None
        if gd_hit and key in detonations:
            try:
                gd_latency = int((parse(gd_hit["CreatedAt"][:19] + "Z")
                                  - parse(detonations[key]["start"])).total_seconds())
            except Exception:
                gd_latency = None

        comparison.append({
            "key": key,
            "mitre": t["mitre"],
            "own_detection": own_detected,
            "guardduty": gd_hit is not None,
            "guardduty_type": gd_hit["Type"] if gd_hit else None,
            "guardduty_latency_s": gd_latency,
        })
        print(f"[gd] {key:<38} own={'yes' if own_detected else 'no':<3} "
              f"guardduty={'yes' if gd_hit else 'no'}"
              + (f" ({gd_hit['Type']})" if gd_hit else ""))

    (EVID / "guardduty" / "comparison.json").write_text(
        json.dumps({"detector_id": detector_id,
                    "real_findings": len(real),
                    "comparison": comparison}, indent=2) + "\n")
    print(f"[gd] {len(real)} real finding(s); wrote evidence/guardduty/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
