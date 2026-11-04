#!/usr/bin/env python3
"""Convert the CloudTrail Sigma rules in sigma/ to a Wazuh local ruleset.

This reuses the week-5 `detections` repo's approach (a small, strict, purpose
-built converter rather than a general pySigma backend) for a new rule class:

  - cloudtrail -> a child of Wazuh's AWS base rule (if_sid 80200) that matches
                  the CloudTrail fields the Sigma `detection` names, as
                  `aws.<field>` entries. Wazuh's aws-s3 wodle flattens each
                  CloudTrail record under `aws.`, so `eventName` becomes
                  `aws.eventName`, `requestParameters.policyArn` becomes
                  `aws.requestParameters.policyArn`, and so on.

It is deliberately strict: a Sigma rule whose shape it does not recognise stops
the run, so the Wazuh output can never silently drift from the Sigma intent.
Run it with --check to fail if wazuh/local_rules.xml is out of date.
"""
from __future__ import annotations

import argparse
import pathlib
import re
import sys
import xml.sax.saxutils as sx

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
SIGMA = ROOT / "sigma"
OUT = ROOT / "wazuh/local_rules.xml"

# Wazuh's base rule for every event the AWS wodle ships (0350-amazon_rules.xml).
AWS_BASE_SID = "80200"


def mitre_ids(tags: list[str]) -> list[str]:
    ids = []
    for t in tags:
        m = re.fullmatch(r"attack\.(t\d{4}(?:\.\d{3})?)", t)
        if m:
            ids.append(m.group(1).upper())
    return ids


def field_pcre2(key, val) -> tuple[str, str]:
    """Map one `field|modifier: value` pair to a Wazuh (name, pcre2) pair.

    The field name keeps its dotted path under `aws.`; the value becomes an
    anchored or substring PCRE2 depending on the Sigma modifier. A list value
    (Sigma OR) becomes an alternation.
    """
    parts = key.split("|")
    name = parts[0]
    mod = parts[1] if len(parts) > 1 else "equals"
    vals = val if isinstance(val, list) else [val]

    def one(v: str) -> str:
        esc = re.escape(str(v))
        if mod == "equals":
            return esc
        if mod == "contains":
            return esc
        if mod == "startswith":
            return esc
        if mod == "endswith":
            return esc
        raise ValueError(f"unsupported Sigma modifier {mod!r} on {name!r}")

    body = "|".join(one(v) for v in vals)
    group = f"(?:{body})" if len(vals) > 1 else body
    if mod == "equals":
        pat = f"^{group}$"
    elif mod == "contains":
        pat = group
    elif mod == "startswith":
        pat = f"^{group}"
    elif mod == "endswith":
        pat = f"{group}$"
    return f"aws.{name}", pat


def rule_xml(doc: dict) -> str:
    ls = doc["logsource"]
    if not (ls.get("product") == "aws" and ls.get("service") == "cloudtrail"):
        raise ValueError(f"{doc['title']}: only aws/cloudtrail logsource is supported")

    det = doc["detection"]
    cond = det["condition"].strip()
    if cond != "selection":
        raise ValueError(f"{doc['title']}: unsupported condition {cond!r}")
    selection = det["selection"]

    wz = doc["wazuh"]
    rid, level = wz["id"], wz["level"]
    desc = sx.escape(doc["title"])

    lines = [f'  <rule id="{rid}" level="{level}">']
    lines.append(f"    <if_sid>{AWS_BASE_SID}</if_sid>")
    for key, val in selection.items():
        name, pat = field_pcre2(key, val)
        lines.append(f'    <field name="{name}" type="pcre2">{sx.escape(pat)}</field>')
    lines.append(f"    <description>{desc}</description>")
    for mid in mitre_ids(doc.get("tags", [])):
        lines.append(f"    <mitre><id>{mid}</id></mitre>")
    lines.append("  </rule>")
    return "\n".join(lines)


def build() -> str:
    docs = [yaml.safe_load(f.read_text()) for f in sorted(SIGMA.glob("*.yml"))]
    docs.sort(key=lambda d: d["wazuh"]["id"])
    body = "\n".join(rule_xml(d) for d in docs)
    return (
        "<!-- Generated from sigma/ by convert/sigma_to_wazuh.py. Do not edit by hand. -->\n"
        '<group name="cloud,detections,aws,">\n' + body + "\n</group>\n"
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true",
                    help="fail if the committed XML is out of date")
    args = ap.parse_args()
    xml = build()
    if args.check:
        current = OUT.read_text() if OUT.exists() else ""
        if current != xml:
            print("sigma_to_wazuh: wazuh/local_rules.xml is out of date; "
                  "run `python convert/sigma_to_wazuh.py`", file=sys.stderr)
            return 1
        print("sigma_to_wazuh: wazuh/local_rules.xml is up to date")
        return 0
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(xml)
    print(f"sigma_to_wazuh: wrote {OUT} from {len(list(SIGMA.glob('*.yml')))} Sigma rules")
    return 0


if __name__ == "__main__":
    sys.exit(main())
