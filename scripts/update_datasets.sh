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

need(){ command -v "$1" >/dev/null 2>&1 || { echo "Missing: $1"; exit 1; }; }
need curl
need python3
need gzip

# --- Config (override via env) ---
# Use NVD 2.0 JSON feeds
NVD_BASE="${NVD_BASE:-https://nvd.nist.gov/feeds/json/cve/2.0}"
# Also supports years: 2002..current, but it can be big.
NVD_YEARS="${NVD_YEARS:-}"  # e.g. "2024 2023 2022"
FETCH_YEARS="${FETCH_YEARS:-0}" # set 1 to fetch NVD years listed above
# CISA KEV JSON
CISA_KEV_URL="${CISA_KEV_URL:-https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json}"
# EPSS daily CSV gz
EPSS_URL="${EPSS_URL:-https://epss.cyentia.com/epss_scores-current.csv.gz}"

# --- Fetch NVD recent & modified (recommended daily) ---
say "Fetching NVD recent + modified..."
curl -fsSL "${NVD_BASE}/nvdcve-2.0-recent.json.gz" -o "${RAW_NVD}/nvdcve-2.0-recent.json.gz"
curl -fsSL "${NVD_BASE}/nvdcve-2.0-modified.json.gz" -o "${RAW_NVD}/nvdcve-2.0-modified.json.gz"

gunzip -f "${RAW_NVD}/nvdcve-2.0-recent.json.gz"
gunzip -f "${RAW_NVD}/nvdcve-2.0-modified.json.gz"

# --- Optional: fetch per-year feeds (weekly/monthly) ---
if [[ "${FETCH_YEARS}" == "1" ]]; then
  if [[ -z "${NVD_YEARS}" ]]; then
    warn "FETCH_YEARS=1 but NVD_YEARS is empty. Example: export NVD_YEARS='2025 2024 2023'"
  else
    for y in ${NVD_YEARS}; do
      say "Fetching NVD year ${y}..."
      curl -fsSL "${NVD_BASE}/nvdcve-2.0-${y}.json.gz" -o "${RAW_NVD}/nvdcve-2.0-${y}.json.gz"
      gunzip -f "${RAW_NVD}/nvdcve-2.0-${y}.json.gz"
    done
  fi
fi

# --- Fetch CISA KEV ---
say "Fetching CISA KEV..."
curl -fsSL "${CISA_KEV_URL}" -o "${RAW_CISA}/known_exploited_vulnerabilities.json"

# --- Fetch EPSS ---
say "Fetching EPSS..."
curl -fsSL "${EPSS_URL}" -o "${RAW_EPSS}/epss_scores-current.csv.gz"
gunzip -f "${RAW_EPSS}/epss_scores-current.csv.gz" || true

# --- Flatten NVD into platform format ---
say "Flattening NVD -> ${OUT_DIR}/nvd_cpe_cve.json ..."
python3 "${ROOT_DIR}/scripts/nvd_flatten.py" \
  --inputs "${RAW_NVD}/nvdcve-2.0-recent.json" "${RAW_NVD}/nvdcve-2.0-modified.json" \
  --out "${OUT_DIR}/nvd_cpe_cve.json"

# --- Convert CISA KEV into platform format (thin list) ---
say "Converting CISA KEV -> ${OUT_DIR}/cisa_kev.json ..."
python3 "${ROOT_DIR}/scripts/cisa_kev_convert.py" \
  --in "${RAW_CISA}/known_exploited_vulnerabilities.json" \
  --out "${OUT_DIR}/cisa_kev.json"

# --- Convert EPSS CSV into JSON ---
say "Converting EPSS -> ${OUT_DIR}/epss.json ..."
python3 "${ROOT_DIR}/scripts/epss_convert.py" \
  --in "${RAW_EPSS}/epss_scores-current.csv" \
  --out "${OUT_DIR}/epss.json"

say "Done ✅"
say "Outputs:"
ls -lah "${OUT_DIR}/nvd_cpe_cve.json" "${OUT_DIR}/cisa_kev.json" "${OUT_DIR}/epss.json" 2>/dev/null || true
