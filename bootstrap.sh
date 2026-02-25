#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${ROOT_DIR}/.env"
DATA_DIR="${ROOT_DIR}/data/cve"

API_BASE="${API_BASE:-http://localhost:8080}"
DEFAULT_ADMIN_EMAIL="${DEFAULT_ADMIN_EMAIL:-admin@local}"
DEFAULT_ADMIN_PASSWORD="${DEFAULT_ADMIN_PASSWORD:-admin123}"

green() { echo -e "\033[1;32m$1\033[0m"; }
yellow() { echo -e "\033[1;33m$1\033[0m"; }
red()    { echo -e "\033[1;31m$1\033[0m"; }

require_cmd() { command -v "$1" >/dev/null 2>&1 || { red "Missing command: $1"; exit 1; }; }

require_cmd docker
require_cmd curl
require_cmd python3
require_cmd openssl

# ── Generate SECRET_KEY if missing ────────────────────────────────────────────
if [[ -f "$ENV_FILE" ]]; then
  CURRENT_KEY="$(grep -E "^SECRET_KEY=" "$ENV_FILE" | cut -d'=' -f2 | tr -d '[:space:]' || true)"
  if [[ -z "$CURRENT_KEY" || "$CURRENT_KEY" == "change-me-very-long-random-secret-please-use-openssl-rand-hex-32" ]]; then
    green "Generating new SECRET_KEY..."
    NEW_KEY="$(openssl rand -hex 32)"
    # Replace the key in the file
    if [[ "$OSTYPE" == "darwin"* ]]; then
      sed -i '' "s|^SECRET_KEY=.*|SECRET_KEY=${NEW_KEY}|" "$ENV_FILE"
    else
      sed -i "s|^SECRET_KEY=.*|SECRET_KEY=${NEW_KEY}|" "$ENV_FILE"
    fi
    green "SECRET_KEY updated"
  fi
else
  red ".env file not found at $ENV_FILE"
  red "Copy .env.example to .env and customize it first"
  exit 1
fi

# ── Start Docker ───────────────────────────────────────────────────────────────
if [[ "${1:-}" != "--no-up" ]]; then
  green "Starting Docker services..."
  docker compose up -d --build
fi

# ── Wait for backend ──────────────────────────────────────────────────────────
green "Waiting for backend to be ready..."
for i in $(seq 1 60); do
  if curl -sf "${API_BASE}/healthz" >/dev/null 2>&1; then
    green "Backend is ready!"
    break
  fi
  echo -n "."
  sleep 2
done

# Verify it's actually up
if ! curl -sf "${API_BASE}/healthz" >/dev/null 2>&1; then
  red "Backend did not become ready in time"
  exit 1
fi

# ── Login ─────────────────────────────────────────────────────────────────────
green "Logging in..."
LOGIN_RESPONSE="$(curl -sf "${API_BASE}/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"${DEFAULT_ADMIN_EMAIL}\",\"password\":\"${DEFAULT_ADMIN_PASSWORD}\"}")"

TOKEN="$(python3 -c "import sys,json; print(json.loads(sys.argv[1]).get('token',''))" "$LOGIN_RESPONSE")"

if [[ -z "$TOKEN" ]]; then
  red "Login failed:"
  echo "$LOGIN_RESPONSE"
  exit 1
fi
green "Login successful"

# ── Upload datasets ───────────────────────────────────────────────────────────
if [[ ! -d "$DATA_DIR" ]]; then
  yellow "No data/cve directory found — skipping dataset upload"
  yellow "Create data/cve/ and add JSON files named by kind (e.g. nvd_cpe_cve.json)"
else
  for file in "$DATA_DIR"/*.json; do
    [[ -f "$file" ]] || continue
    filename="$(basename "$file")"
    kind="${filename%.json}"
    green "Uploading dataset: $filename (kind=$kind)"
    curl -sf -X POST "${API_BASE}/datasets/upload?kind=${kind}&name=${kind}" \
      -H "Authorization: Bearer ${TOKEN}" \
      -F "file=@${file}" >/dev/null && echo "  ✓ Uploaded $filename" || echo "  ✗ Failed $filename"
  done
fi

# ── Create default scan profile ───────────────────────────────────────────────
green "Creating default scan profile..."
PROFILE_JSON='{
  "name": "default",
  "plugin_selection_json": {
    "net.port.discovery.v2": true,
    "fingerprint.http": true,
    "fingerprint.banner.multi": true,
    "fingerprint.web.tech": true,
    "fingerprint.favicon.hash": true,
    "cpe.builder": true,
    "cve.match.nvd_cpe": true,
    "cve.match.cms": true,
    "priority.cisa_kev": true,
    "tls.basic.version": true,
    "auth.ssh.inventory": false,
    "cve.match.packages": false
  },
  "options_json": {
    "asset": { "criticality": 2 }
  }
}'

curl -sf -X POST "${API_BASE}/scan/profiles" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d "$PROFILE_JSON" >/dev/null && green "Default profile created" || yellow "Profile may already exist"

green ""
green "═══════════════════════════════════════════════════"
green " Bootstrap complete!"
green "═══════════════════════════════════════════════════"
echo ""
echo " API Docs:   ${API_BASE}/docs"
echo " Frontend:   http://localhost:5173"
echo " Neo4j:      http://localhost:7474  (neo4j/password)"
echo ""
echo " Credentials: ${DEFAULT_ADMIN_EMAIL} / ${DEFAULT_ADMIN_PASSWORD}"
echo ""
yellow " ⚠ Change DEFAULT_ADMIN_PASSWORD in .env before production!"
