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

# ── Helper: build profile JSON with python (dynamic CRED_ID + all plugins) ───
build_profile() {
  python3 -c "
import json, sys
cred_id = int(sys.argv[1])
name = sys.argv[2]
criticality = int(sys.argv[3])
nmap_mode = sys.argv[4]
ssh_enabled = sys.argv[5] == 'true'
print(json.dumps({
    'name': name,
    'plugin_selection_json': {
        'net.port.discovery.v2': True,
        'net.port.discovery.nmap': True,
        'recon.dns.enum': True,
        'recon.directory.crawl': True,
        'fingerprint.http': True,
        'fingerprint.banner.multi': True,
        'fingerprint.web.tech': True,
        'fingerprint.favicon.hash': True,
        'fingerprint.deep': True,
        'cpe.builder': True,
        'cve.match.nvd_cpe': True,
        'cve.match.cms': True,
        'cve.endpoint_prober': True,
        'cve.verifier': True,
        'priority.cisa_kev': True,
        'owasp.web.scanner': True,
        'vuln.file.inclusion': True,
        'tls.basic.version': True,
        'infra.ssh.audit': True,
        'infra.db.auth_check': True,
        'infra.smb.check': True,
        'web.api_key_exposure': True,
        'web.jwt_scanner': True,
        'web.graphql_scanner': True,
        'web.security_headers': True,
        'iot.mqtt_scanner': True,
        'infra.snmp.community': True,
        'infra.ftp.anonymous': True,
        'infra.redis.deep': True,
        'web.host_header_injection': True,
        'web.crlf_injection': True,
        'infra.docker.api': True,
        'cloud.storage.misconfig': True,
        'web.waf.detection': True,
        'web.ssti.scanner': True,
        'auth.ssh.inventory': ssh_enabled,
        'cve.match.packages': ssh_enabled,
        'local.security.checks': ssh_enabled,
    },
    'options_json': {
        'auth': {
            'ssh_credential_id': cred_id,
            'ssh_port': 22,
        },
        'asset': {'criticality': criticality},
        'nmap': {'mode': nmap_mode},
    },
}))
" "$CRED_ID" "$1" "$2" "$3" "$4"
}

# ── Create default scan profile ───────────────────────────────────────────────
green "Creating default scan profile..."
DEFAULT_PROFILE="$(build_profile "default" 2 "top100" "false")"
curl -sf -X POST "${API_BASE}/scan/profiles" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d "$DEFAULT_PROFILE" >/dev/null && green "Default profile created (SSH cred #${CRED_ID})" || yellow "Profile may already exist"

# ── Create OWASP-focused profile ──────────────────────────────────────────────
green "Creating OWASP Web Assessment profile..."
OWASP_PROFILE="$(build_profile "owasp-web-full" 3 "top1000" "false")"
curl -sf -X POST "${API_BASE}/scan/profiles" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d "$OWASP_PROFILE" >/dev/null && green "OWASP profile created (SSH cred #${CRED_ID})" || yellow "Profile may already exist"

# ── Create Infrastructure Audit profile (with SSH) ────────────────────────────
green "Creating Infrastructure Audit profile (with SSH credential #${CRED_ID})..."
INFRA_PROFILE="$(build_profile "infra-full-audit" 4 "full" "true")"
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
echo " Scan Profiles (all using SSH credential #${CRED_ID}):"
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

