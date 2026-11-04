#!/usr/bin/env bash
# The two negative tests that prove the detections are earned:
#
#  (a) Benign window: query every detection over a window of ordinary read-only
#      activity (scripts/benign.sh recorded it). A real detection must stay
#      silent here, so the expected result is zero detections.
#
#  (b) Disabled rule: run the collection with one detection switched off and
#      show the verify gate fails and names the technique it missed. A gate that
#      cannot fail proves nothing.
set -uo pipefail
cd "$(dirname "$0")/.."
export AWS_REGION=us-east-1 AWS_DEFAULT_REGION=us-east-1
fail=0

echo "== negative test (a): benign window must raise no detection =="
start=$(python3 -c "import json;print(json.load(open('evidence/benign_window.json'))['start'])")
end=$(python3 -c "import json;print(json.load(open('evidence/benign_window.json'))['end'])")
python3 scripts/collect.py --start "$start" --end "$end" \
  --out evidence/negative_benign.json >/dev/null
n=$(python3 -c "import json;print(sum(1 for t in json.load(open('evidence/negative_benign.json'))['techniques'] if t['athena_detected']))")
if [ "$n" -eq 0 ]; then
  echo "  PASS: 0 detections over the benign window"
else
  echo "  FAIL: $n detection(s) fired on benign activity"; fail=1
fi

echo
echo "== negative test (b): a disabled detection must fail the verify gate =="
disabled=iam-backdoor-user
python3 scripts/collect.py --disable "$disabled" \
  --out evidence/negative_disabled.json >/dev/null
if python3 scripts/verify.py --input evidence/negative_disabled.json \
     > evidence/negative_disabled_verify.txt 2>&1; then
  echo "  FAIL: verify passed with $disabled disabled"; fail=1
else
  if grep -q "$disabled" evidence/negative_disabled_verify.txt; then
    echo "  PASS: verify failed and named the missed technique ($disabled)"
  else
    echo "  FAIL: verify failed but did not name $disabled"; fail=1
  fi
fi

echo
[ "$fail" -eq 0 ] && echo "negative tests: PASS" || { echo "negative tests: FAIL"; exit 1; }
