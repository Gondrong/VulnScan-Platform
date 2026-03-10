#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${ROOT_DIR}/.env"
DATA_DIR="${ROOT_DIR}/data/cve"

API_BASE="${API_BASE:-http://localhost:8888}"
DEFAULT_ADMIN_EMAIL="${DEFAULT_ADMIN_EMAIL:-admin@local}"
DEFAULT_ADMIN_PASSWORD="${DEFAULT_ADMIN_PASSWORD:-admin123}"

# SSH credential defaults — override via env or edit after bootstrap
SSH_CRED_NAME="${SSH_CRED_NAME:-default-ssh}"
SSH_CRED_USER="${SSH_CRED_USER:-root}"
SSH_CRED_SECRET="${SSH_CRED_SECRET:-changeme}"
SSH_CRED_TYPE="${SSH_CRED_TYPE:-password}"  # "password" or "SSH_KEY"

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

# ── Create or detect SSH credential ────────────────────────────────────────────
green "Checking for existing SSH credentials..."
EXISTING_CREDS="$(curl -sf "${API_BASE}/credentials" \
  -H "Authorization: Bearer ${TOKEN}" 2>/dev/null)" || EXISTING_CREDS="[]"

EXISTING_COUNT="$(python3 -c "import sys,json; print(len(json.loads(sys.argv[1])))" "$EXISTING_CREDS" 2>/dev/null)" || EXISTING_COUNT=0

if [[ "$EXISTING_COUNT" -gt 0 ]]; then
  # Use the first existing credential
  CRED_ID="$(python3 -c "import sys,json; creds=json.loads(sys.argv[1]); print(creds[0]['id'])" "$EXISTING_CREDS")"
  CRED_NAME="$(python3 -c "import sys,json; creds=json.loads(sys.argv[1]); print(creds[0]['name'])" "$EXISTING_CREDS")"
  green "Found existing SSH credential #${CRED_ID} (${CRED_NAME}) — reusing it"
else
  green "No credentials found — creating default SSH credential..."
  CRED_RESPONSE="$(curl -sf -X POST "${API_BASE}/credentials" \
    -H "Authorization: Bearer ${TOKEN}" \
    -H "Content-Type: application/json" \
    -d "{
      \"name\": \"${SSH_CRED_NAME}\",
      \"kind\": \"ssh\",
      \"username\": \"${SSH_CRED_USER}\",
      \"secret_type\": \"${SSH_CRED_TYPE}\",
      \"secret\": \"${SSH_CRED_SECRET}\"
    }" 2>/dev/null)" || true

  CRED_ID="$(python3 -c "import sys,json; print(json.loads(sys.argv[1]).get('id',1))" "$CRED_RESPONSE" 2>/dev/null)" || CRED_ID=1
  green "SSH credential #${CRED_ID} created (${SSH_CRED_USER}@${SSH_CRED_TYPE})"
fi

# ── Create default scan profile ───────────────────────────────────────────────
green "Creating default scan profile..."
PROFILE_JSON='{
  "name": "default",
  "plugin_selection_json": {
    "net.port.discovery.v2": true,
    "net.port.discovery.nmap": true,
    "fingerprint.http": true,
    "fingerprint.banner.multi": true,
    "fingerprint.web.tech": true,
    "fingerprint.favicon.hash": true,
    "cpe.builder": true,
    "cve.match.nvd_cpe": true,
    "cve.match.cms": true,
    "priority.cisa_kev": true,
    "tls.basic.version": true,
    "local.security.checks": true,
    "owasp.web.scanner": true,
    "vuln.file.inclusion": true,
    "recon.directory.crawl": true,
    "auth.ssh.inventory": false,
    "cve.match.packages": true
  },
  "options_json": {
    "asset": { "criticality": 2 },
    "nmap": { "mode": "top100" }
  }
}'

curl -sf -X POST "${API_BASE}/scan/profiles" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d "$PROFILE_JSON" >/dev/null && green "Default profile created" || yellow "Profile may already exist"

# ── Create OWASP-focused profile ──────────────────────────────────────────────
green "Creating OWASP Web Assessment profile..."
OWASP_PROFILE='{
  "name": "owasp-web-full",
  "plugin_selection_json": {
    "net.port.discovery.v2": true,
    "net.port.discovery.nmap": true,
    "fingerprint.http": true,
    "fingerprint.banner.multi": true,
    "fingerprint.web.tech": true,
    "fingerprint.favicon.hash": true,
    "cpe.builder": true,
    "cve.match.nvd_cpe": true,
    "cve.match.cms": true,
    "priority.cisa_kev": true,
    "tls.basic.version": true,
    "local.security.checks": true,
    "owasp.web.scanner": true,
    "vuln.file.inclusion": true,
    "recon.directory.crawl": true,
    "auth.ssh.inventory": false,
    "cve.match.packages": true
  },
  "options_json": {
    "asset": { "criticality": 3 },
    "nmap": { "mode": "top1000" }
  }
}'

curl -sf -X POST "${API_BASE}/scan/profiles" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d "$OWASP_PROFILE" >/dev/null && green "OWASP profile created" || yellow "Profile may already exist"

# ── Create Infrastructure Audit profile (with SSH) ────────────────────────────
green "Creating Infrastructure Audit profile (with SSH credential #${CRED_ID})..."

# Use python to build JSON with dynamic CRED_ID
INFRA_PROFILE="$(python3 -c "
import json, sys
cred_id = int(sys.argv[1])
print(json.dumps({
    'name': 'infra-full-audit',
    'plugin_selection_json': {
        'net.port.discovery.v2': True,
        'net.port.discovery.nmap': True,
        'fingerprint.http': True,
        'fingerprint.banner.multi': True,
        'fingerprint.web.tech': True,
        'fingerprint.favicon.hash': True,
        'cpe.builder': True,
        'cve.match.nvd_cpe': True,
        'cve.match.cms': True,
        'priority.cisa_kev': True,
        'tls.basic.version': True,
        'local.security.checks': True,
        'owasp.web.scanner': True,
        'vuln.file.inclusion': True,
        'recon.directory.crawl': True,
        'auth.ssh.inventory': True,
        'cve.match.packages': True,
    },
    'options_json': {
        'auth': {
            'ssh_credential_id': cred_id,
            'ssh_port': 22,
        },
        'asset': {'criticality': 4},
        'nmap': {'mode': 'full'},
    },
}))
" "$CRED_ID")"

curl -sf -X POST "${API_BASE}/scan/profiles" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d "$INFRA_PROFILE" >/dev/null && green "Infrastructure Audit profile created (SSH cred #${CRED_ID})" || yellow "Profile may already exist"

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
echo " Scan Profiles:"
echo "   • default          — Quick scan (top 100 ports + OWASP + CVE)"
echo "   • owasp-web-full   — Web app assessment (top 1000 ports + full OWASP)"
echo "   • infra-full-audit — Full infrastructure (65535 ports + SSH cred #${CRED_ID} + all plugins)"
echo ""
echo " SSH Credential #${CRED_ID}:"
echo "   Name:     ${SSH_CRED_NAME}"
echo "   Username: ${SSH_CRED_USER}"
echo "   Type:     ${SSH_CRED_TYPE}"
echo ""
yellow " ⚠ Update the SSH credential with real credentials in Configuration → Credentials"
yellow " ⚠ Change DEFAULT_ADMIN_PASSWORD in .env before production!"
echo ""
echo " To customize SSH creds at bootstrap time:"
echo "   SSH_CRED_USER=admin SSH_CRED_SECRET=mypassword ./bootstrap.sh"
echo "   SSH_CRED_TYPE=SSH_KEY SSH_CRED_SECRET=\"\$(cat ~/.ssh/id_rsa)\" ./bootstrap.sh"
