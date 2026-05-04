#!/usr/bin/env python3
"""
fast_update_datasets.py — Parallel dataset fetcher for VulnScan Platform.

Fetches from ALL FREE sources in parallel:
  1. NVD API        — NIST CVSS scores + CPE data (primary)
  2. CVE.org API    — CNA/vendor CVSS scores (second opinion)
  3. CISA KEV       — Known exploited vulnerabilities
  4. EPSS           — Exploit prediction scores

Usage:
  NVD_API_KEY=your-key python3 scripts/fast_update_datasets.py
  python3 scripts/fast_update_datasets.py --skip-cveorg   # NVD only
"""

import argparse
import concurrent.futures
import gzip
import json
import logging
import os
import subprocess
import sys
import time
import urllib.request
import urllib.error
from datetime import datetime, timedelta, timezone
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="\033[1;32m[update]\033[0m %(message)s")
logger = logging.getLogger("fast_update")

ROOT_DIR = Path(__file__).resolve().parent.parent
RAW_NVD = ROOT_DIR / "data" / "raw" / "nvd"
RAW_CISA = ROOT_DIR / "data" / "raw" / "cisa"
RAW_EPSS = ROOT_DIR / "data" / "raw" / "epss"
OUT_DIR = ROOT_DIR / "data" / "cve"

NVD_API_BASE = os.environ.get("NVD_API_BASE", "https://services.nvd.nist.gov/rest/json/cves/2.0")
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
CVEORG_API = "https://cveawg.mitre.org/api/cve"


def fetch_url(url, headers=None, timeout=30):
    req = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


# ── NVD ──────────────────────────────────────────────────────────────────────

def fetch_nvd_page(page_num, start_idx, page_size, start_date, end_date, api_key, rate_delay):
    headers = {"Accept": "application/json"}
    if api_key:
        headers["apiKey"] = api_key
    url = f"{NVD_API_BASE}?pubStartDate={start_date}&pubEndDate={end_date}&startIndex={start_idx}&resultsPerPage={page_size}"
    if page_num > 1:
        time.sleep(rate_delay)
    try:
        data = fetch_url(url, headers, timeout=60)
        result = json.loads(data)
        logger.info("  NVD page %d: %d vulns", page_num, len(result.get("vulnerabilities", [])))
        return page_num, result
    except Exception as e:
        logger.error("  NVD page %d failed: %s", page_num, e)
        return page_num, None


def fetch_nvd_parallel(nvd_days, api_key, max_workers=5):
    end_date = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")
    start_date = (datetime.now(timezone.utc) - timedelta(days=nvd_days)).strftime("%Y-%m-%dT%H:%M:%S.000")
    rate_delay = 0.6 if api_key else 6.0
    workers = max_workers if api_key else 1
    if not api_key:
        logger.warning("No NVD_API_KEY — slow mode. Get free key: https://nvd.nist.gov/developers/request-an-api-key")
    logger.info("Fetching NVD (last %d days, %d workers)...", nvd_days, workers)
    page_size = 2000
    _, first_page = fetch_nvd_page(1, 0, page_size, start_date, end_date, api_key, 0)
    if not first_page:
        return []
    total = first_page.get("totalResults", 0)
    logger.info("  Total: %d CVEs", total)
    pages = [first_page]
    if total <= page_size:
        return pages
    remaining = list(range(page_size, total, page_size))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(fetch_nvd_page, i+2, s, page_size, start_date, end_date, api_key, rate_delay): i for i, s in enumerate(remaining)}
        for f in concurrent.futures.as_completed(futures):
            _, r = f.result()
            if r:
                pages.append(r)
    return pages


# ── CISA KEV + EPSS ──────────────────────────────────────────────────────────

def fetch_cisa_kev():
    logger.info("Fetching CISA KEV...")
    try:
        data = fetch_url(CISA_KEV_URL, timeout=30)
        (RAW_CISA / "known_exploited_vulnerabilities.json").write_bytes(data)
        logger.info("  KEV: %d bytes", len(data))
        return True
    except Exception as e:
        logger.error("  KEV failed: %s", e)
        return False


def fetch_epss():
    logger.info("Fetching EPSS...")
    try:
        data = fetch_url(EPSS_URL, timeout=60)
        csv_data = gzip.decompress(data)
        (RAW_EPSS / "epss_scores-current.csv").write_bytes(csv_data)
        logger.info("  EPSS: %d bytes", len(csv_data))
        return True
    except Exception as e:
        logger.error("  EPSS failed: %s", e)
        return False


# ── CVE.org (CNA/ADP scores) ────────────────────────────────────────────────

def score_to_sev(s):
    if s >= 9: return "critical"
    if s >= 7: return "high"
    if s >= 4: return "medium"
    if s > 0: return "low"
    return "info"


def fetch_cveorg_single(cve_id):
    """Fetch CNA + ADP CVSS from CVE.org API (free)."""
    try:
        data = json.loads(fetch_url(f"{CVEORG_API}/{cve_id}", {"Accept": "application/json", "User-Agent": "VulnScan/1.0"}, 15))
        containers = data.get("containers", {})
        cna_score = adp_score = None
        # CNA score
        for m in containers.get("cna", {}).get("metrics", []):
            for k in ("cvssV3_1", "cvssV3_0", "cvssV4_0"):
                d = m.get(k)
                if d and d.get("baseScore"):
                    cna_score = float(d["baseScore"])
                    break
            if cna_score: break
        # ADP score (CISA Vulnrichment etc.)
        for adp in containers.get("adp", []):
            for m in adp.get("metrics", []):
                for k in ("cvssV3_1", "cvssV3_0", "cvssV4_0"):
                    d = m.get(k)
                    if d and d.get("baseScore"):
                        adp_score = float(d["baseScore"])
                        break
                if adp_score: break
            if adp_score: break
        if cna_score or adp_score:
            best = max(filter(None, [cna_score, adp_score]))
            return cve_id, {"cvss": best, "severity": score_to_sev(best), "source": "cna" if not adp_score else "cna+adp" if cna_score else "adp", "cna_cvss": cna_score, "adp_cvss": adp_score}
    except Exception:
        pass
    return cve_id, None


def fetch_cveorg_parallel(cve_ids, workers=5):
    logger.info("Fetching CVE.org CNA scores for %d CVEs (%d workers)...", len(cve_ids), workers)
    results = {}
    done = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(fetch_cveorg_single, c): c for c in cve_ids}
        for f in concurrent.futures.as_completed(futures):
            cve_id, r = f.result()
            if r:
                results[cve_id] = r
            done += 1
            if done % 500 == 0 or done == len(cve_ids):
                logger.info("  CVE.org progress: %d/%d (found=%d)", done, len(cve_ids), len(results))
    return results


# ── Convert scripts ──────────────────────────────────────────────────────────

def run_script(name, args):
    script = ROOT_DIR / "scripts" / name
    if not script.exists():
        return False
    try:
        r = subprocess.run([sys.executable, str(script)] + args, capture_output=True, text=True, timeout=120)
        if r.stdout.strip():
            for line in r.stdout.strip().split("\n"):
                logger.info("  %s", line)
        return r.returncode == 0
    except Exception as e:
        logger.error("%s: %s", name, e)
        return False


def flatten_nvd(pages):
    if not pages: return
    for i, p in enumerate(pages, 1):
        with open(RAW_NVD / f"nvd_api_page_{i}.json", "w") as f:
            json.dump(p, f)
    inputs = [str(RAW_NVD / f"nvd_api_page_{i}.json") for i in range(1, len(pages)+1)]
    logger.info("Flattening NVD (%d pages)...", len(pages))
    run_script("nvd_flatten.py", ["--inputs"] + inputs + ["--out", str(OUT_DIR / "nvd_cpe_cve.json")])


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--nvd-days", type=int, default=int(os.environ.get("NVD_DAYS", 120)))
    ap.add_argument("--workers", type=int, default=5)
    ap.add_argument("--skip-cveorg", action="store_true", help="Skip CVE.org CNA score fetch")
    ap.add_argument("--cveorg-max", type=int, default=0, help="Max CVEs for CVE.org (0=all)")
    ap.add_argument("--cveorg-workers", type=int, default=5)
    args = ap.parse_args()

    api_key = os.environ.get("NVD_API_KEY", "")
    for d in [RAW_NVD, RAW_CISA, RAW_EPSS, OUT_DIR]:
        d.mkdir(parents=True, exist_ok=True)

    t0 = time.time()

    # Phase 1: Fetch NVD + CISA + EPSS in parallel
    logger.info("=" * 60)
    logger.info("Phase 1: Fetching NVD + CISA KEV + EPSS")
    logger.info("=" * 60)
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        nvd_f = pool.submit(fetch_nvd_parallel, args.nvd_days, api_key, args.workers)
        pool.submit(fetch_cisa_kev)
        pool.submit(fetch_epss)
        pages = nvd_f.result()
    logger.info("Phase 1 done in %.1fs", time.time() - t0)

    # Phase 2: Convert
    logger.info("=" * 60)
    logger.info("Phase 2: Convert to platform format")
    logger.info("=" * 60)
    flatten_nvd(pages)
    kev_raw = RAW_CISA / "known_exploited_vulnerabilities.json"
    if kev_raw.exists():
        run_script("cisa_kev_convert.py", ["--in", str(kev_raw), "--out", str(OUT_DIR / "cisa_kev.json")])
    epss_raw = RAW_EPSS / "epss_scores-current.csv"
    if epss_raw.exists():
        run_script("epss_convert.py", ["--in", str(epss_raw), "--out", str(OUT_DIR / "epss.json")])
    nvd_out = OUT_DIR / "nvd_cpe_cve.json"
    if nvd_out.exists():
        run_script("generate_cms_cve_map.py", ["--nvd", str(nvd_out), "--out", str(OUT_DIR / "cms_cve_map.json")])
    run_script("generate_compliance_map.py", ["--out", str(OUT_DIR / "compliance_map.json")])

    # Phase 3: CVE.org CNA scores (free second opinion)
    if not args.skip_cveorg and nvd_out.exists():
        logger.info("=" * 60)
        logger.info("Phase 3: CVE.org CNA/ADP scores (free)")
        logger.info("=" * 60)
        with open(nvd_out) as f:
            cve_ids = [e["cve"] for e in json.load(f) if e.get("cve", "").startswith("CVE-")]
        cache_path = OUT_DIR / "cvedetails_cvss.json"
        existing = {}
        if cache_path.exists():
            try:
                with open(cache_path) as f:
                    existing = json.load(f)
            except Exception:
                pass
        new_ids = [c for c in cve_ids if c not in existing]
        if args.cveorg_max:
            new_ids = new_ids[:args.cveorg_max]
        if new_ids:
            new_results = fetch_cveorg_parallel(new_ids, args.cveorg_workers)
            existing.update(new_results)
            with open(cache_path, "w") as f:
                json.dump(existing, f, indent=2)
            logger.info("CVE.org cache: %d total -> %s", len(existing), cache_path)
        else:
            logger.info("All CVEs already cached")

    total = time.time() - t0
    logger.info("=" * 60)
    logger.info("All done in %.1fs", total)
    for name in ["nvd_cpe_cve.json", "cisa_kev.json", "epss.json", "cms_cve_map.json", "compliance_map.json", "cvedetails_cvss.json"]:
        p = OUT_DIR / name
        if p.exists():
            s = p.stat().st_size
            logger.info("  %s: %s", name, f"{s/1024/1024:.1f} MB" if s > 1048576 else f"{s/1024:.1f} KB")

if __name__ == "__main__":
    main()