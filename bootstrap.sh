#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${ROOT_DIR}/.env.example"
DATA_DIR="${ROOT_DIR}/data/cve"

API_BASE="http://localhost:8080"
DEFAULT_ADMIN_EMAIL="admin@local"
DEFAULT_ADMIN_PASSWORD="admin123"

green() { echo -e "\033[1;32m$1\033[0m"; }
yellow() { echo -e "\033[1;33m$1\033[0m"; }
red() { echo -e "\033[1;31m$1\033[0m"; }

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || { red "Missing $1"; exit 1; }
}

require_cmd docker
require_cmd curl
require_cmd python3
require_cmd openssl

# ----------------------------
# Generate SECRET_KEY if missing
# ----------------------------
if [[ -f "$ENV_FILE" ]]; then
  if ! grep -q "^SECRET_KEY=" "$ENV_FILE"; then
    green "Generating SECRET_KEY..."
    KEY=$(openssl rand -hex 32)
    echo "SECRET_KEY=${KEY}" >> "$ENV_FILE"
  else
    KEY_VALUE=$(grep "^SECRET_KEY=" "$ENV_FILE" | cut -d '=' -f2)
    if [[ -z "$KEY_VALUE" ]]; then
      green "SECRET_KEY empty. Generating..."
      KEY=$(openssl rand -hex 32)
      sed -i.bak "s/^SECRET_KEY=.*/SECRET_KEY=${KEY}/" "$ENV_FILE"
    fi
  fi
else
  red ".env.example not found"
  exit 1
fi

# ----------------------------
# Start Docker
# ----------------------------
if [[ "${1:-}" != "--no-up" ]]; then
  green "Starting Docker services..."
  docker compose up -d --build
fi

# Wait backend
green "Waiting backend..."
for i in {1..60}; do
  if curl -s "${API_BASE}/healthz" >/dev/null 2>&1; then
    break
  fi
  sleep 2
done

# ----------------------------
# Login
# ----------------------------
green "Logging in..."
LOGIN_RESPONSE=$(curl -s "${API_BASE}/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"${DEFAULT_ADMIN_EMAIL}\",\"password\":\"${DEFAULT_ADMIN_PASSWORD}\"}")

TOKEN=$(echo "$LOGIN_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('token',''))")

if [[ -z "$TOKEN" ]]; then
  red "Login failed"
  echo "$LOGIN_RESPONSE"
  exit 1
fi

green "Login success"

# ----------------------------
# Auto upload all datasets
# ----------------------------
if [[ ! -d "$DATA_DIR" ]]; then
  yellow "No data/cve folder found"
else
  for file in "$DATA_DIR"/*.json; do
    filename=$(basename "$file")
    kind="${filename%.json}"

    green "Uploading dataset: $filename as kind=$kind"

    curl -s -X POST "${API_BASE}/datasets/upload?kind=${kind}&name=${kind}" \
      -H "Authorization: Bearer ${TOKEN}" \
      -F "file=@${file}" >/dev/null
  done
fi

green "Datasets uploaded"

# ----------------------------
# Create default profile
# ----------------------------
PROFILE_JSON=$(cat <<EOF
{
  "name": "default",
  "plugin_selection_json": {
    "net.port.discovery.v2": true,
    "fingerprint.banner.multi": true,
    "fingerprint.web.tech": true,
    "fingerprint.favicon.hash": true,
    "cpe.builder": true,
    "cve.match.nvd_cpe": true,
    "priority.cisa_kev": true
  },
  "options_json": {
    "cve": {
      "dataset_kinds": ["osv","nvd_cpe_cve","cisa_kev","cms_cve_map","favicon_hash_map","compliance_map"]
    },
    "asset": {
      "criticality": 2
    }
  }
}
EOF
)

green "Creating profile..."
curl -s -X POST "${API_BASE}/scan/profiles" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d "$PROFILE_JSON" >/dev/null

green "Bootstrap complete!"
echo ""
echo "Open Swagger:"
echo "  http://localhost:8080/docs"
echo ""
echo "Login UI:"
echo "  admin@local / admin123"
