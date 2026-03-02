#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

RAW_NVD="${ROOT_DIR}/data/raw/nvd"
RAW_CISA="${ROOT_DIR}/data/raw/cisa"
RAW_EPSS="${ROOT_DIR}/data/raw/epss"
OUT_DIR="${ROOT_DIR}/data/cve"

mkdir -p "$RAW_NVD" "$RAW_CISA" "$RAW_EPSS" "$OUT_DIR"

say(){ echo -e "\033[1;32m[update]\033[0m $*"; }
warn(){ echo -e "\033[1;33m[update]\033[0m $*"; }
err(){ echo -e "\033[1;31m[update]\033[0m $*"; }

need(){ command -v "$1" >/dev/null 2>&1 || { echo "Missing: $1"; exit 1; }; }
need curl
need python3

# --- Config (override via env) ---
NVD_API_BASE="${NVD_API_BASE:-https://services.nvd.nist.gov/rest/json/cves/2.0}"
NVD_DAYS="${NVD_DAYS:-120}"
NVD_API_KEY="${NVD_API_KEY:-}"
NVD_LOCAL_FILES="${NVD_LOCAL_FILES:-}"

CISA_KEV_URL="${CISA_KEV_URL:-https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json}"
EPSS_URL="${EPSS_URL:-https://epss.cyentia.com/epss_scores-current.csv.gz}"


# ═══════════════════════════════════════════════════════════════════════════════
# FETCH NVD DATA
# ═══════════════════════════════════════════════════════════════════════════════

# Use a bash ARRAY to safely handle paths with spaces (e.g. "VulnScan Platform")
NVD_INPUT_FILES=()

if [[ -n "${NVD_LOCAL_FILES}" ]]; then
  say "Using local NVD files: ${NVD_LOCAL_FILES}"
  IFS=':' read -ra _local_arr <<< "${NVD_LOCAL_FILES}"
  for f in "${_local_arr[@]}"; do
    if [[ -f "$f" ]]; then
      NVD_INPUT_FILES+=("$f")
    else
      warn "Local NVD file not found: $f"
    fi
  done
else
  say "Fetching NVD CVEs from API (last ${NVD_DAYS} days)..."

  END_DATE="$(date -u +%Y-%m-%dT%H:%M:%S.000)"
  START_DATE="$(date -u -d "${NVD_DAYS} days ago" +%Y-%m-%dT%H:%M:%S.000 2>/dev/null || \
               date -u -v-${NVD_DAYS}d +%Y-%m-%dT%H:%M:%S.000 2>/dev/null || \
               python3 -c "from datetime import datetime,timedelta;print((datetime.utcnow()-timedelta(days=${NVD_DAYS})).strftime('%Y-%m-%dT%H:%M:%S.000'))")"

  say "Date range: ${START_DATE} -> ${END_DATE}"

  HEADERS=(-H "Accept: application/json")
  if [[ -n "${NVD_API_KEY}" ]]; then
    HEADERS+=(-H "apiKey: ${NVD_API_KEY}")
    RATE_DELAY=0.6
  else
    RATE_DELAY=6
    warn "No NVD_API_KEY set — using slow rate limit (6s between requests)"
    warn "Get a free key at https://nvd.nist.gov/developers/request-an-api-key"
  fi

  START_IDX=0
  PAGE_SIZE=2000
  PAGE_NUM=0
  TOTAL_RESULTS=999999

  while [[ $START_IDX -lt $TOTAL_RESULTS ]]; do
    PAGE_NUM=$((PAGE_NUM + 1))
    OUT_FILE="${RAW_NVD}/nvd_api_page_${PAGE_NUM}.json"

    say "  Page ${PAGE_NUM} (startIndex=${START_IDX})..."
    HTTP_CODE=$(curl -sS -w "%{http_code}" -o "$OUT_FILE" \
      "${HEADERS[@]}" \
      "${NVD_API_BASE}?pubStartDate=${START_DATE}&pubEndDate=${END_DATE}&startIndex=${START_IDX}&resultsPerPage=${PAGE_SIZE}")

    if [[ "$HTTP_CODE" != "200" ]]; then
      err "NVD API returned HTTP ${HTTP_CODE}. Response:"
      head -c 500 "$OUT_FILE" 2>/dev/null || true
      echo ""
      if [[ $PAGE_NUM -eq 1 ]]; then
        say "Retrying with lastModStartDate..."
        HTTP_CODE=$(curl -sS -w "%{http_code}" -o "$OUT_FILE" \
          "${HEADERS[@]}" \
          "${NVD_API_BASE}?lastModStartDate=${START_DATE}&lastModEndDate=${END_DATE}&startIndex=${START_IDX}&resultsPerPage=${PAGE_SIZE}")
        if [[ "$HTTP_CODE" != "200" ]]; then
          err "NVD API still returned HTTP ${HTTP_CODE}. Aborting NVD fetch."
          break
        fi
      else
        err "Aborting NVD fetch after page ${PAGE_NUM}."
        break
      fi
    fi

    if [[ $PAGE_NUM -eq 1 ]]; then
      TOTAL_RESULTS=$(python3 -c "import json;print(json.load(open('${OUT_FILE}')).get('totalResults',0))" 2>/dev/null || echo "0")
      say "  Total CVEs available: ${TOTAL_RESULTS}"
    fi

    NVD_INPUT_FILES+=("$OUT_FILE")
    START_IDX=$((START_IDX + PAGE_SIZE))

    if [[ $START_IDX -lt $TOTAL_RESULTS ]]; then
      sleep "$RATE_DELAY"
    fi
  done

  if [[ ${#NVD_INPUT_FILES[@]} -eq 0 ]]; then
    warn "No NVD data fetched — nvd_cpe_cve.json will not be updated"
  fi
fi


# ═══════════════════════════════════════════════════════════════════════════════
# FETCH CISA KEV
# ═══════════════════════════════════════════════════════════════════════════════

say "Fetching CISA KEV..."
if curl -fsSL "${CISA_KEV_URL}" -o "${RAW_CISA}/known_exploited_vulnerabilities.json"; then
  say "  ✓ KEV downloaded"
else
  err "Failed to fetch CISA KEV — continuing anyway"
fi


# ═══════════════════════════════════════════════════════════════════════════════
# FETCH EPSS
# ═══════════════════════════════════════════════════════════════════════════════

say "Fetching EPSS..."
if curl -fsSL "${EPSS_URL}" -o "${RAW_EPSS}/epss_scores-current.csv.gz"; then
  gunzip -f "${RAW_EPSS}/epss_scores-current.csv.gz" 2>/dev/null || true
  say "  ✓ EPSS downloaded"
else
  err "Failed to fetch EPSS — continuing anyway"
fi


# ═══════════════════════════════════════════════════════════════════════════════
# CONVERT TO PLATFORM FORMAT
# ═══════════════════════════════════════════════════════════════════════════════

# --- Flatten NVD ---
# CRITICAL: Use "${array[@]}" with quotes to preserve paths containing spaces
if [[ ${#NVD_INPUT_FILES[@]} -gt 0 ]]; then
  say "Flattening NVD (${#NVD_INPUT_FILES[@]} files) -> ${OUT_DIR}/nvd_cpe_cve.json ..."
  python3 "${ROOT_DIR}/scripts/nvd_flatten.py" \
    --inputs "${NVD_INPUT_FILES[@]}" \
    --out "${OUT_DIR}/nvd_cpe_cve.json"
else
  warn "Skipping NVD flatten — no input files"
fi

# --- Convert CISA KEV ---
if [[ -f "${RAW_CISA}/known_exploited_vulnerabilities.json" ]]; then
  say "Converting CISA KEV -> ${OUT_DIR}/cisa_kev.json ..."
  python3 "${ROOT_DIR}/scripts/cisa_kev_convert.py" \
    --in "${RAW_CISA}/known_exploited_vulnerabilities.json" \
    --out "${OUT_DIR}/cisa_kev.json"
else
  warn "Skipping KEV convert — raw file not found"
fi

# --- Convert EPSS ---
if [[ -f "${RAW_EPSS}/epss_scores-current.csv" ]]; then
  say "Converting EPSS -> ${OUT_DIR}/epss.json ..."
  python3 "${ROOT_DIR}/scripts/epss_convert.py" \
    --in "${RAW_EPSS}/epss_scores-current.csv" \
    --out "${OUT_DIR}/epss.json"
else
  warn "Skipping EPSS convert — raw file not found"
fi


# --- Generate CMS CVE Map from NVD data ---
if [[ -f "${OUT_DIR}/nvd_cpe_cve.json" ]]; then
  say "Generating CMS CVE map -> ${OUT_DIR}/cms_cve_map.json ..."
  python3 "${ROOT_DIR}/scripts/generate_cms_cve_map.py" \
    --nvd "${OUT_DIR}/nvd_cpe_cve.json" \
    --out "${OUT_DIR}/cms_cve_map.json"
else
  warn "Skipping CMS CVE map — nvd_cpe_cve.json not found"
fi

# --- Generate Compliance Map ---
say "Generating compliance map -> ${OUT_DIR}/compliance_map.json ..."
python3 "${ROOT_DIR}/scripts/generate_compliance_map.py" \
  --out "${OUT_DIR}/compliance_map.json"


say "Done ✅"
say "Outputs:"
ls -lah "${OUT_DIR}/nvd_cpe_cve.json" "${OUT_DIR}/cisa_kev.json" "${OUT_DIR}/epss.json" "${OUT_DIR}/cms_cve_map.json" "${OUT_DIR}/compliance_map.json" 2>/dev/null || true
