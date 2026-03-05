#!/usr/bin/env python3
"""
multi_cvss_fetch.py — Fetch CVSS scores from FREE multi-source APIs.

Sources (all free, no API key required):
  1. CVE.org API    — CNA scores (vendor's own CVSS assessment)
  2. NVD API        — NIST's CVSS assessment (already in your dataset)

The CVE.org API provides the CNA (CVE Numbering Authority) score, which is
the original vendor assessment. This often differs from NVD's score because
NVD does their own independent analysis.

Cross-referencing both gives you a second opinion on every CVE.

Usage:
  # Fetch CNA scores for all CVEs in your NVD dataset
  python3 scripts/multi_cvss_fetch.py \
    --nvd-data data/cve/nvd_cpe_cve.json \
    --out data/cve/cvedetails_cvss.json

  # Limit to first 200 CVEs (quick test)
  python3 scripts/multi_cvss_fetch.py \
    --nvd-data data/cve/nvd_cpe_cve.json \
    --out data/cve/cvedetails_cvss.json \
    --max 200

  # Faster with more workers (default: 5)
  python3 scripts/multi_cvss_fetch.py \
    --nvd-data data/cve/nvd_cpe_cve.json \
    --out data/cve/cvedetails_cvss.json \
    --workers 10
"""

import argparse
import concurrent.futures
import json
import logging
import os
import sys
import time
import urllib.request
import urllib.error

logging.basicConfig(level=logging.INFO, format="\033[1;32m[cvss]\033[0m %(message)s")
logger = logging.getLogger("multi_cvss")

# CVE.org API — free, no auth needed, 50 req/s with burst to 100
CVEORG_API = "https://cveawg.mitre.org/api/cve"


def score_to_severity(score):
    if score >= 9.0: return "critical"
    if score >= 7.0: return "high"
    if score >= 4.0: return "medium"
    if score > 0.0:  return "low"
    return "info"


def extract_cvss_from_cveorg(data):
    """
    Extract the best CVSS score from a CVE.org API v5 response.
    
    The response has two main sections:
    - cnaContainer: the CNA's (vendor's) own scoring
    - adpContainer: ADP scores (e.g., CISA Vulnrichment)
    
    We extract both and return the CNA score as primary.
    """
    results = {}
    
    containers = data.get("containers", {})
    
    # 1. CNA score (vendor's assessment)
    cna = containers.get("cna", {})
    cna_metrics = cna.get("metrics", [])
    for metric in cna_metrics:
        for key in ("cvssV3_1", "cvssV3_0", "cvssV4_0", "cvssV2_0"):
            cvss_data = metric.get(key)
            if cvss_data:
                score = cvss_data.get("baseScore")
                if score and 0 < float(score) <= 10:
                    results["cna_cvss"] = float(score)
                    results["cna_severity"] = score_to_severity(float(score))
                    results["cna_vector"] = cvss_data.get("vectorString", "")
                    break
        if "cna_cvss" in results:
            break
    
    # 2. ADP scores (CISA Vulnrichment, etc.)
    adp_list = containers.get("adp", [])
    for adp in adp_list:
        adp_metrics = adp.get("metrics", [])
        provider = adp.get("providerMetadata", {}).get("shortName", "adp")
        for metric in adp_metrics:
            for key in ("cvssV3_1", "cvssV3_0", "cvssV4_0"):
                cvss_data = metric.get(key)
                if cvss_data:
                    score = cvss_data.get("baseScore")
                    if score and 0 < float(score) <= 10:
                        results["adp_cvss"] = float(score)
                        results["adp_severity"] = score_to_severity(float(score))
                        results["adp_provider"] = provider
                        break
            if "adp_cvss" in results:
                break
        if "adp_cvss" in results:
            break
    
    return results if results else None


def fetch_cve_org(cve_id):
    """Fetch a CVE from the CVE.org API. Returns (cve_id, result_dict) or (cve_id, None)."""
    url = f"{CVEORG_API}/{cve_id}"
    headers = {
        "Accept": "application/json",
        "User-Agent": "VulnScan-Platform/1.0",
    }
    
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        
        result = extract_cvss_from_cveorg(data)
        if result:
            # Build the final entry using the best score
            cna = result.get("cna_cvss")
            adp = result.get("adp_cvss")
            
            # Use the higher of CNA and ADP (conservative)
            if cna and adp:
                best = max(cna, adp)
                source = "cna+adp"
            elif cna:
                best = cna
                source = "cna"
            elif adp:
                best = adp
                source = "adp"
            else:
                return cve_id, None
            
            return cve_id, {
                "cvss": best,
                "severity": score_to_severity(best),
                "source": source,
                "cna_cvss": cna,
                "adp_cvss": adp,
                "adp_provider": result.get("adp_provider"),
            }
    
    except urllib.error.HTTPError as e:
        if e.code == 404:
            pass  # CVE not in CVE.org yet
        elif e.code == 429:
            time.sleep(2)  # Rate limited, brief pause
        else:
            logger.debug("%s: HTTP %d", cve_id, e.code)
    except Exception as e:
        logger.debug("%s: %s", cve_id, str(e)[:100])
    
    return cve_id, None


def fetch_batch_parallel(cve_ids, max_workers=5):
    """Fetch CVSS data for multiple CVEs in parallel."""
    results = {}
    fetched = 0
    failed = 0
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(fetch_cve_org, cve_id): cve_id for cve_id in cve_ids}
        
        for i, future in enumerate(concurrent.futures.as_completed(futures)):
            cve_id, result = future.result()
            if result:
                results[cve_id] = result
                fetched += 1
            else:
                failed += 1
            
            done = fetched + failed
            if done % 200 == 0 or done == len(cve_ids):
                logger.info("  Progress: %d/%d (fetched=%d, no_score=%d)",
                           done, len(cve_ids), fetched, failed)
    
    return results


def main():
    ap = argparse.ArgumentParser(description="Fetch multi-source CVSS from CVE.org (free)")
    ap.add_argument("--nvd-data", required=True, help="Path to nvd_cpe_cve.json")
    ap.add_argument("--out", required=True, help="Output JSON path (cvedetails_cvss.json)")
    ap.add_argument("--max", type=int, default=0, help="Max CVEs to fetch (0=all)")
    ap.add_argument("--workers", type=int, default=5, help="Parallel workers (default: 5)")
    ap.add_argument("--skip-existing", action="store_true", default=True, 
                    help="Skip CVEs already in output file (default: true)")
    args = ap.parse_args()
    
    # Load NVD data to get CVE list
    try:
        with open(args.nvd_data) as f:
            nvd_data = json.load(f)
    except Exception as e:
        logger.error("Failed to load NVD data: %s", e)
        sys.exit(1)
    
    cve_ids = [e["cve"] for e in nvd_data if e.get("cve", "").startswith("CVE-")]
    logger.info("Found %d CVEs in NVD dataset", len(cve_ids))
    
    # Load existing cache
    existing = {}
    if os.path.exists(args.out):
        try:
            with open(args.out) as f:
                existing = json.load(f)
            if existing:
                logger.info("Loaded %d existing entries from cache", len(existing))
        except Exception:
            pass
    
    # Skip already-fetched CVEs
    if args.skip_existing and existing:
        cve_ids = [c for c in cve_ids if c not in existing]
        logger.info("After skipping cached: %d CVEs to fetch", len(cve_ids))
    
    if args.max:
        cve_ids = cve_ids[:args.max]
    
    if not cve_ids:
        logger.info("Nothing to fetch — all CVEs are cached")
        return
    
    logger.info("Fetching %d CVEs from CVE.org API (%d workers)...", len(cve_ids), args.workers)
    logger.info("  Source: %s (free, no API key needed)", CVEORG_API)
    
    start = time.time()
    new_results = fetch_batch_parallel(cve_ids, args.workers)
    elapsed = time.time() - start
    
    # Merge with existing
    existing.update(new_results)
    
    # Save
    with open(args.out, "w") as f:
        json.dump(existing, f, indent=2)
    
    logger.info("Done in %.1fs: %d new scores, %d total cached -> %s",
               elapsed, len(new_results), len(existing), args.out)
    
    # Show some examples
    if new_results:
        samples = list(new_results.items())[:5]
        logger.info("Sample results:")
        for cve_id, data in samples:
            logger.info("  %s: CVSS=%.1f (%s) source=%s",
                       cve_id, data["cvss"], data["severity"], data["source"])


if __name__ == "__main__":
    main()