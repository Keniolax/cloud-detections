#!/usr/bin/env bash
# Run the Wazuh AWS S3 wodle inside the manager to read the CloudTrail logs
# from the trail bucket, then pull out the alerts this week's rules raised.
#
# The wodle uses the SIEM identity's read-only keys (from .env), never the
# admin keys. In the cloud VM it reaches S3 through the agent proxy, so it is
# given HTTPS_PROXY and the proxy CA bundle for boto3.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/.." && pwd)"
LAB_DIR="${LAB_DIR:-$repo/../home-soc-lab}"
LAB_DIR="$(cd "$LAB_DIR" && pwd)"

[ -f "$repo/.env" ] || { echo "wazuh_ingest: $repo/.env not found (run make env)" >&2; exit 1; }
# shellcheck disable=SC1091
set -a; . "$repo/.env"; set +a
: "${AWS_ACCESS_KEY_ID:?}" "${AWS_SECRET_ACCESS_KEY:?}" "${TRAIL_BUCKET:?}"

acct="$(aws sts get-caller-identity --query Account --output text)"
region="${AWS_REGION:-us-east-1}"

cd "$LAB_DIR"
export COMPOSE_FILE="compose.yaml:${CLOUD_DIR:-$repo/../../cloud}/home-soc-lab/compose.cloud.yaml"

# Give the manager the proxy CA so boto3's TLS to S3 verifies.
ca=/root/.ccr/ca-bundle.crt
if [ -f "$ca" ]; then
  docker compose cp "$ca" wazuh.manager:/tmp/ccr-ca.crt
  CA_ENV="-e AWS_CA_BUNDLE=/tmp/ccr-ca.crt -e REQUESTS_CA_BUNDLE=/tmp/ccr-ca.crt"
else
  CA_ENV=""
fi
PROXY_ENV=""
[ -n "${HTTPS_PROXY:-}" ] && PROXY_ENV="-e HTTPS_PROXY=$HTTPS_PROXY -e HTTP_PROXY=${HTTP_PROXY:-$HTTPS_PROXY}"

echo "wazuh_ingest: running the aws-s3 wodle over s3://$TRAIL_BUCKET ..."
# shellcheck disable=SC2086
docker compose exec -T \
  -e AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID" \
  -e AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY" \
  $PROXY_ENV $CA_ENV \
  wazuh.manager \
  /var/ossec/wodles/aws/aws-s3 \
    --bucket "$TRAIL_BUCKET" \
    --type cloudtrail \
    --regions "$region" \
    --aws_account_id "$acct" \
    --only_logs_after "$(date -u +%Y-%b-%d)" \
    --debug 1 2>&1 | tail -20 || true

echo "wazuh_ingest: waiting for analysisd to process the events ..."
sleep 20

mkdir -p "$repo/evidence/wazuh"
docker compose cp wazuh.manager:/var/ossec/logs/alerts/alerts.json \
  "$repo/evidence/wazuh/alerts_raw.json" 2>/dev/null || {
    echo "wazuh_ingest: no alerts.json yet" >&2; : > "$repo/evidence/wazuh/alerts_raw.json"; }

# Keep only the alerts from this week's rules (100700-100706).
python3 - "$repo/evidence/wazuh/alerts_raw.json" "$repo/evidence/wazuh/alerts.json" <<'PY'
import json, sys
raw, out = sys.argv[1], sys.argv[2]
ids = {str(i) for i in range(100700, 100707)}
kept = []
try:
    for line in open(raw):
        line = line.strip()
        if not line:
            continue
        try:
            a = json.loads(line)
        except json.JSONDecodeError:
            continue
        if str(a.get("rule", {}).get("id")) in ids:
            kept.append(a)
except FileNotFoundError:
    pass
with open(out, "w") as f:
    for a in kept:
        f.write(json.dumps(a) + "\n")
print(f"wazuh_ingest: kept {len(kept)} matching alert(s) -> {out}")
PY
