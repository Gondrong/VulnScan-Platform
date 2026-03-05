#!/usr/bin/env python3
"""
cvedetails_fetch.py — Fetch CVSS scores from CVEDetails.com for cross-referencing.

This script reads the existing NVD dataset to get a list of CVE IDs, then
queries CVEDetails.com for each CVE to get their CVSS assessment.

The output is a JSON file: data/cve/cvedetails_cvss.json
Format: {"CVE-YYYY-NNNNN": {"cvss": 9.8, "severity": "critical", "source": "cvedetails"}, ...}

Usage:
  python3 cvedetails_fetch.py --nvd-data data/cve/nvd_cpe_cve.json --out data/cve/cvedetails_cvss.json

  # Or with rate limiting (be respectful to the API):
  python3 cvedetails_fetch.py --nvd-data data/cve/nvd_cpe_cve.json --out data/cve/cvedetails_cvss.json --delay 1.5

Notes:
  - CVEDetails.com has rate limits. Use --delay to control request speed.
  - The script merges with existing output file (incremental updates).
  - If CVEDetails.com is unreachable, existing cached data is preserved.
"""

import argparse
import json
import logging
import os
import sys
import time
import urllib.request
import urllib.error
import re

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger("cvedetails_fetch")


def score_to_severity(score):
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "info"


def fetch_cvedetails_score(cve_id, timeout=10):
    """
    Fetch CVSS score for a CVE from CVEDetails.com.

    Uses the public page and extracts the CVSS score from the HTML.
    Returns {"cvss": float, "severity": str} or None on failure.
    """
    url = f"https://www.cvedetails.com/cve/{cve_id}/"
    headers = {
        "User-Agent": "VulnScan-Platform/1.0 (Security Scanner Dataset Update)",
        "Accept": "text/html",
    }

    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            html = resp.read().decode("utf-8", errors="ignore")

        # Extract CVSS score from the page
        # CVEDetails typically shows: "CVSS Score" followed by the numeric value
        patterns = [
            r'cvss[_-]?score["\s:>]*([0-9]+\.?[0-9]*)',
            r'CVSS\s+(?:v[23]\s+)?(?:Base\s+)?Score[:\s]*([0-9]+\.?[0-9]*)',
            r'"cvssScore"[:\s]*([0-9]+\.?[0-9]*)',
            r'class="cvssbox"[^>]*>([0-9]+\.?[0-9]*)',
        ]

        for pattern in patterns:
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                score = float(match.group(1))
                if 0.0 <= score <= 10.0:
                    return {
                        "cvss": score,
                        "severity": score_to_severity(score),
                        "source": "cvedetails",
                    }

        # Try JSON-LD structured data
        json_ld_match = re.search(r'<script[^>]*type="application/ld\+json"[^>]*>(.*?)</script>', html, re.DOTALL)
        if json_ld_match:
            try:
                ld_data = json.loads(json_ld_match.group(1))
                if isinstance(ld_data, dict):
                    score = ld_data.get("cvssScore") or ld_data.get("cvss_score")
                    if score:
                        score = float(score)
                        return {
                            "cvss": score,
                            "severity": score_to_severity(score),
                            "source": "cvedetails",
                        }
            except (json.JSONDecodeError, ValueError):
                pass

        logger.debug("No CVSS score found in HTML for %s", cve_id)
        return None

    except urllib.error.HTTPError as e:
        if e.code == 404:
            logger.debug("%s not found on CVEDetails", cve_id)
        else:
            logger.warning("%s: HTTP %d from CVEDetails", cve_id, e.code)
        return None
    except Exception as e:
        logger.debug("%s: fetch failed: %s", cve_id, e)
        return None


def fetch_cvedetails_api(cve_id, api_key=None, timeout=10):
    """
    Fetch CVSS score using CVEDetails.com JSON API (if API key is available).
    Returns {"cvss": float, "severity": str} or None.
    """
    if not api_key:
        return None

    url = f"https://www.cvedetails.com/api/v1/vulnerability/{cve_id}"
    headers = {
        "User-Agent": "VulnScan-Platform/1.0",
        "Accept": "application/json",
        "Authorization": f"Bearer {api_key}",
    }

    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))

        score = data.get("cvssScore") or data.get("cvss_score") or data.get("cvss3_score")
        if score:
            score = float(score)
            return {
                "cvss": score,
                "severity": score_to_severity(score),
                "source": "cvedetails_api",
            }
    except Exception as e:
        logger.debug("%s: API fetch failed: %s", cve_id, e)

    return None


def main():
    ap = argparse.ArgumentParser(description="Fetch CVSS data from CVEDetails.com")
    ap.add_argument("--nvd-data", required=True, help="Path to nvd_cpe_cve.json")
    ap.add_argument("--out", required=True, help="Output JSON path")
    ap.add_argument("--delay", type=float, default=2.0, help="Seconds between requests (default: 2.0)")
    ap.add_argument("--max", type=int, default=0, help="Max CVEs to fetch (0=all)")
    ap.add_argument("--api-key", default=os.environ.get("CVEDETAILS_API_KEY", ""), help="CVEDetails API key (optional)")
    ap.add_argument("--skip-existing", action="store_true", help="Skip CVEs already in output file")
    args = ap.parse_args()

    # Load existing cache
    existing = {}
    if os.path.exists(args.out):
        try:
            with open(args.out) as f:
                existing = json.load(f)
            logger.info("Loaded %d existing CVEDetails entries", len(existing))
        except Exception:
            pass

    # Load NVD data to get CVE list
    try:
        with open(args.nvd_data) as f:
            nvd_data = json.load(f)
    except Exception as e:
        logger.error("Failed to load NVD data: %s", e)
        sys.exit(1)

    cve_ids = [entry["cve"] for entry in nvd_data if entry.get("cve", "").startswith("CVE-")]
    logger.info("Found %d CVEs in NVD dataset", len(cve_ids))

    if args.skip_existing:
        cve_ids = [c for c in cve_ids if c not in existing]
        logger.info("After skipping existing: %d CVEs to fetch", len(cve_ids))

    if args.max:
        cve_ids = cve_ids[:args.max]

    # Fetch from CVEDetails
    fetched = 0
    failed = 0
    for i, cve_id in enumerate(cve_ids):
        if i > 0:
            time.sleep(args.delay)

        logger.info("[%d/%d] Fetching %s...", i + 1, len(cve_ids), cve_id)

        # Try API first, fall back to HTML scraping
        result = fetch_cvedetails_api(cve_id, args.api_key) or fetch_cvedetails_score(cve_id)

        if result:
            existing[cve_id] = result
            fetched += 1
            logger.info("  %s: CVSS=%.1f (%s)", cve_id, result["cvss"], result["severity"])
        else:
            failed += 1

    # Save
    with open(args.out, "w") as f:
        json.dump(existing, f, indent=2)

    logger.info("Done: %d fetched, %d failed, %d total cached -> %s",
                fetched, failed, len(existing), args.out)


if __name__ == "__main__":
    main()
