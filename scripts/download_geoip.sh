#!/usr/bin/env bash
# Download MaxMind GeoLite2-City database for IP geolocation.
#
# Usage:
#   MAXMIND_LICENSE_KEY=your_key ./scripts/download_geoip.sh
#
# Get a free license key at: https://www.maxmind.com/en/geolite2/signup
set -euo pipefail

DEST="${1:-data/GeoLite2-City.mmdb}"
DEST_DIR="$(dirname "$DEST")"

if [[ -z "${MAXMIND_LICENSE_KEY:-}" ]]; then
  echo "Error: MAXMIND_LICENSE_KEY is required."
  echo ""
  echo "1. Sign up (free): https://www.maxmind.com/en/geolite2/signup"
  echo "2. Generate a license key in your MaxMind account"
  echo "3. Run: MAXMIND_LICENSE_KEY=your_key $0"
  exit 1
fi

URL="https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=${MAXMIND_LICENSE_KEY}&suffix=tar.gz"
TMP="$(mktemp -d)"

echo "Downloading GeoLite2-City database..."
curl -sL "$URL" -o "$TMP/geolite2.tar.gz"
tar -xzf "$TMP/geolite2.tar.gz" -C "$TMP"
MMDB="$(find "$TMP" -name '*.mmdb' | head -1)"

if [[ -z "$MMDB" ]]; then
  echo "Error: No .mmdb file found in download. Check your license key."
  rm -rf "$TMP"
  exit 1
fi

mkdir -p "$DEST_DIR"
mv "$MMDB" "$DEST"
rm -rf "$TMP"

echo "GeoLite2-City.mmdb installed at: $DEST"
echo "Location lookup is now active — restart containers to pick it up."
