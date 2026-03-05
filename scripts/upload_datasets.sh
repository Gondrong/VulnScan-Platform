#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${ROOT_DIR}/data/cve"

# Try loading .env (support both .env and .env.example)
for envfile in "${ROOT_DIR}/.env" "${ROOT_DIR}/.env.example"; do
  if [[ -f "$envfile" ]]; then
    export $(grep -v '^\s*#' "$envfile" | grep -v '^\s*$' | sed 's/\r$//' | xargs -d '\n') 2>/dev/null || true
    break
  fi
done

API_BASE="${API_BASE:-http://localhost:8080}"
DEFAULT_ADMIN_EMAIL="${DEFAULT_ADMIN_EMAIL:-admin@local}"
DEFAULT_ADMIN_PASSWORD="${DEFAULT_ADMIN_PASSWORD:-admin123}"

need(){ command -v "$1" >/dev/null 2>&1 || { echo "Missing: $1"; exit 1; }; }
need curl
need python3

say(){ echo -e "\033[1;32m[upload]\033[0m $*"; }
err(){ echo -e "\033[1;31m[upload]\033[0m $*"; }

# --- Login ---
say "Logging in to ${API_BASE} as ${DEFAULT_ADMIN_EMAIL}..."
LOGIN_RESP="$(curl -fsS "${API_BASE}/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"${DEFAULT_ADMIN_EMAIL}\",\"password\":\"${DEFAULT_ADMIN_PASSWORD}\"}" 2>&1)" || {
  err "Login request failed. Is the backend running at ${API_BASE}?"
  err "Response: ${LOGIN_RESP}"
  exit 1
}

# FIX: Use echo + pipe instead of heredoc + sys.argv (which caused IndexError)
TOKEN="$(echo "$LOGIN_RESP" | python3 -c "import json,sys; print(json.loads(sys.stdin.read()).get('token',''))")"

if [[ -z "$TOKEN" ]]; then
  err "Login failed — no token in response: $LOGIN_RESP"
  exit 1
fi

say "Authenticated ✓"

upload_one(){
  local kind="$1"
  local name="$2"
  local path="$3"

  if [[ ! -f "$path" ]]; then
    err "Missing file: $path — skipping"
    return 0
  fi

  local size
  size="$(du -h "$path" | cut -f1)"
  say "Uploading ${kind} (${name}) -> $(basename "$path") [${size}]"

  local resp
  resp="$(curl -fsS -X POST "${API_BASE}/datasets/upload?kind=${kind}&name=${name}" \
    -H "Authorization: Bearer ${TOKEN}" \
    -F "file=@${path}" 2>&1)" || {
    err "Upload failed for ${kind}: ${resp}"
    return 0
  }

  say "  ✓ ${kind} uploaded: ${resp}"
}

# Map output filenames to dataset kinds used by the platform
upload_one "nvd_cpe_cve" "nvd_auto" "${OUT_DIR}/nvd_cpe_cve.json"
upload_one "cisa_kev" "kev_auto" "${OUT_DIR}/cisa_kev.json"
upload_one "epss" "epss_auto" "${OUT_DIR}/epss.json"
upload_one "cms_cve_map" "cms_auto" "${OUT_DIR}/cms_cve_map.json"
upload_one "compliance_map" "compliance_auto" "${OUT_DIR}/compliance_map.json"
upload_one "cvedetails_cvss" "cvedetails_auto" "${OUT_DIR}/cvedetails_cvss.json"

# Optional: if you maintain these manually, uncomment:
# upload_one "osv" "osv_manual" "${OUT_DIR}/osv.json"
# upload_one "cms_cve_map" "cms_manual" "${OUT_DIR}/cms_cve_map.json"
# upload_one "favicon_hash_map" "favicon_manual" "${OUT_DIR}/favicon_hash_map.json"
# upload_one "compliance_map" "compliance_manual" "${OUT_DIR}/compliance_map.json"

say "Upload done ✅"
