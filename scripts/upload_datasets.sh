#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="${ROOT_DIR}/.env.example"
OUT_DIR="${ROOT_DIR}/data/cve"

API_BASE="${API_BASE:-http://localhost:8080}"
DEFAULT_ADMIN_EMAIL="${DEFAULT_ADMIN_EMAIL:-admin@local}"
DEFAULT_ADMIN_PASSWORD="${DEFAULT_ADMIN_PASSWORD:-admin123}"

if [[ -f "$ENV_FILE" ]]; then
  # load env
  export $(grep -v '^\s*#' "$ENV_FILE" | grep -v '^\s*$' | sed 's/\r$//' | xargs -d '\n')
fi

need(){ command -v "$1" >/dev/null 2>&1 || { echo "Missing: $1"; exit 1; }; }
need curl
need python3

say(){ echo -e "\033[1;32m[upload]\033[0m $*"; }

LOGIN_RESP="$(curl -fsS "${API_BASE}/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"${DEFAULT_ADMIN_EMAIL}\",\"password\":\"${DEFAULT_ADMIN_PASSWORD}\"}")"

TOKEN="$(python3 - <<PY
import json,sys
print(json.loads(sys.argv[1]).get("token",""))
PY
"$LOGIN_RESP"
)"

if [[ -z "$TOKEN" ]]; then
  echo "Login failed: $LOGIN_RESP"
  exit 1
fi

upload_one(){
  local kind="$1"
  local name="$2"
  local path="$3"
  [[ -f "$path" ]] || { echo "Missing file: $path"; return; }
  say "Uploading ${kind} -> $(basename "$path")"
  curl -fsS -X POST "${API_BASE}/datasets/upload?kind=${kind}&name=${name}" \
    -H "Authorization: Bearer ${TOKEN}" \
    -F "file=@${path}" >/dev/null
}

# Map output filenames to dataset kinds used by the platform
upload_one "nvd_cpe_cve" "nvd_auto" "${OUT_DIR}/nvd_cpe_cve.json"
upload_one "cisa_kev" "kev_auto" "${OUT_DIR}/cisa_kev.json"
upload_one "epss" "epss_auto" "${OUT_DIR}/epss.json"

# Optional: if you maintain these manually:
# upload_one "osv" "osv_manual" "${OUT_DIR}/osv.json"
# upload_one "cms_cve_map" "cms_manual" "${OUT_DIR}/cms_cve_map.json"
# upload_one "favicon_hash_map" "favicon_manual" "${OUT_DIR}/favicon_hash_map.json"
# upload_one "compliance_map" "compliance_manual" "${OUT_DIR}/compliance_map.json"

say "Upload done ✅"
