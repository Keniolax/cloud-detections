#!/usr/bin/env bash
# Negative test (a): a window of ordinary, read-only activity. The detections
# must stay silent over this window. Records the window to evidence so collect.py
# can query it, then runs a handful of list/describe calls that look nothing
# like the attacks.
set -uo pipefail
region="${AWS_REGION:-us-east-1}"
EVID="$(cd "$(dirname "$0")/.." && pwd)/evidence"
mkdir -p "$EVID"

start="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# Ordinary operator activity: listing and describing. None of these is one of
# the detected event names.
aws s3api list-buckets                       >/dev/null 2>&1 || true
aws ec2 describe-instances --region "$region" >/dev/null 2>&1 || true
aws ec2 describe-security-groups --region "$region" >/dev/null 2>&1 || true
aws iam list-users                           >/dev/null 2>&1 || true
aws iam list-roles                           >/dev/null 2>&1 || true
aws cloudtrail describe-trails --region "$region" >/dev/null 2>&1 || true
aws sts get-caller-identity                  >/dev/null 2>&1 || true

sleep 3
end="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

printf '{"start": "%s", "end": "%s"}\n' "$start" "$end" > "$EVID/benign_window.json"
echo "benign window $start .. $end written to evidence/benign_window.json"
