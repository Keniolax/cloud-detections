#!/usr/bin/env bash
# Bring up just the Wazuh manager and indexer from home-soc-lab (with the
# cloud/ overlay) and load this week's CloudTrail rules into the manager. The
# victim, dashboard and probe are not needed for cloud-log detection, so they
# are left down.
#
# Env:
#   LAB_DIR    path to the home-soc-lab clone (default work/home-soc-lab)
#   CLOUD_DIR  path to the bootcamp cloud/ overlay (default ../../.. /cloud)
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/.." && pwd)"
LAB_DIR="${LAB_DIR:-$repo/../home-soc-lab}"
LAB_DIR="$(cd "$LAB_DIR" && pwd)"
CLOUD_DIR="${CLOUD_DIR:-$repo/../../cloud}"
overlay="$CLOUD_DIR/home-soc-lab/compose.cloud.yaml"

[ -f "$overlay" ] || { echo "wazuh_up: overlay $overlay not found" >&2; exit 1; }

cd "$LAB_DIR"
[ -f .env ] || scripts/init-env.sh

export COMPOSE_FILE="compose.yaml:$overlay"
echo "wazuh_up: starting init-certs, init-users, indexer, manager ..."
docker compose up -d --wait --wait-timeout 300 \
  init-certs init-users wazuh.indexer wazuh.manager

# Load this week's CloudTrail rules and restart the manager so it reads them.
echo "wazuh_up: loading local_rules.xml into the manager ..."
docker compose cp "$repo/wazuh/local_rules.xml" \
  wazuh.manager:/var/ossec/etc/rules/local_rules.xml
docker compose exec -T wazuh.manager chown wazuh:wazuh /var/ossec/etc/rules/local_rules.xml
docker compose restart wazuh.manager
docker compose up -d --wait --wait-timeout 180 wazuh.manager

echo "wazuh_up: manager and indexer are up, rules loaded."
