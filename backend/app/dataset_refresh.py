"""
Dataset refresh module — fetches and converts datasets for the VulnScan Platform.

Adapted from scripts/fast_update_datasets.py for use inside the RQ worker container.
Each refresh_* function returns (success: bool, output_path: str | None, error: str | None).
"""

from __future__ import annotations

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

logger = logging.getLogger("vulnscan.dataset_refresh")

# ── Paths (inside Docker container) ─────────────────────────────────────────
RAW_NVD = Path("/data/raw/nvd")
RAW_CISA = Path("/data/raw/cisa")
RAW_EPSS = Path("/data/raw/epss")
OUT_DIR = Path("/data/cve")
SCRIPTS_DIR = Path("/scripts")

# ── Dataset kinds ───────────────────────────────────────────────────────────
DATASET_KINDS = [
    "nvd_cpe_cve",
    "cisa_kev",
    "epss",
    "cvedetails_cvss",
    "cms_cve_map",
    "compliance_map",
]

VALID_KINDS = set(DATASET_KINDS)

# Dependencies: key depends on value being available first
KIND_DEPENDS: dict[str, str] = {
    "cms_cve_map": "nvd_cpe_cve",
    "cvedetails_cvss": "nvd_cpe_cve",
}

# ── Source URLs ─────────────────────────────────────────────────────────────
NVD_API_BASE = os.environ.get(
    "NVD_API_BASE", "https://services.nvd.nist.gov/rest/json/cves/2.0"
)
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
CVEORG_API = "https://cveawg.mitre.org/api/cve"


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")


def _ensure_dirs():
    for d in [RAW_NVD, RAW_CISA, RAW_EPSS, OUT_DIR]:
        d.mkdir(parents=True, exist_ok=True)


def _fetch_url(url: str, headers: dict | None = None, timeout: int = 30) -> bytes:
    req = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def _run_script(name: str, args: list[str]) -> bool:
    script = SCRIPTS_DIR / name
    if not script.exists():
        logger.error("Script not found: %s", script)
        return False
    try:
        r = subprocess.run(
            [sys.executable, str(script)] + args,
            capture_output=True,
            text=True,
            timeout=180,
        )
        if r.stdout.strip():
            for line in r.stdout.strip().split("\n"):
                logger.info("  %s", line)
        if r.returncode != 0 and r.stderr.strip():
            logger.error("  %s stderr: %s", name, r.stderr.strip()[:500])
        return r.returncode == 0
    except Exception as e:
        logger.error("%s: %s", name, e)
        return False


# ── NVD ─────────────────────────────────────────────────────────────────────

def _fetch_nvd_page(page_num, start_idx, page_size, start_date, end_date, api_key, rate_delay):
    headers = {"Accept": "application/json"}
    if api_key:
        headers["apiKey"] = api_key
    url = (
        f"{NVD_API_BASE}?pubStartDate={start_date}&pubEndDate={end_date}"
        f"&startIndex={start_idx}&resultsPerPage={page_size}"
    )
    if page_num > 1:
        time.sleep(rate_delay)
    try:
        data = _fetch_url(url, headers, timeout=60)
        result = json.loads(data)
        logger.info("  NVD page %d: %d vulns", page_num, len(result.get("vulnerabilities", [])))
        return page_num, result
    except Exception as e:
        logger.error("  NVD page %d failed: %s", page_num, e)
        return page_num, None


def refresh_nvd(api_key: str, nvd_days: int = 120) -> tuple[bool, str | None, str | None]:
    """Fetch NVD data and flatten into CPE-CVE format."""
    _ensure_dirs()
    end_date = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")
    start_date = (datetime.now(timezone.utc) - timedelta(days=nvd_days)).strftime(
        "%Y-%m-%dT%H:%M:%S.000"
    )
    rate_delay = 0.6 if api_key else 6.0
    workers = 5 if api_key else 1

    if not api_key:
        logger.warning("No NVD_API_KEY — slow mode (6s between requests)")

    logger.info("Fetching NVD (last %d days, %d workers)...", nvd_days, workers)

    try:
        # Fetch first page to get total count
        _, first_page = _fetch_nvd_page(1, 0, 2000, start_date, end_date, api_key, 0)
        if not first_page:
            return False, None, "NVD first page fetch failed"

        total = first_page.get("totalResults", 0)
        logger.info("  NVD total: %d CVEs", total)
        pages = [first_page]

        if total > 2000:
            remaining = list(range(2000, total, 2000))
            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
                futures = {
                    pool.submit(
                        _fetch_nvd_page, i + 2, s, 2000, start_date, end_date, api_key, rate_delay
                    ): i
                    for i, s in enumerate(remaining)
                }
                for f in concurrent.futures.as_completed(futures):
                    _, r = f.result()
                    if r:
                        pages.append(r)

        # Write raw pages
        for i, p in enumerate(pages, 1):
            with open(RAW_NVD / f"nvd_api_page_{i}.json", "w") as f:
                json.dump(p, f)

        # Flatten
        inputs = [str(RAW_NVD / f"nvd_api_page_{i}.json") for i in range(1, len(pages) + 1)]
        out_path = str(OUT_DIR / f"nvd_cpe_cve_{_ts()}.json")
        ok = _run_script("nvd_flatten.py", ["--inputs"] + inputs + ["--out", out_path])
        if not ok:
            return False, None, "nvd_flatten.py failed"

        logger.info("NVD refresh complete: %s", out_path)
        return True, out_path, None

    except Exception as e:
        return False, None, str(e)


# ── CISA KEV ────────────────────────────────────────────────────────────────

def refresh_cisa_kev() -> tuple[bool, str | None, str | None]:
    """Fetch and convert CISA KEV feed."""
    _ensure_dirs()
    try:
        logger.info("Fetching CISA KEV...")
        data = _fetch_url(CISA_KEV_URL, timeout=30)
        raw_path = RAW_CISA / "known_exploited_vulnerabilities.json"
        raw_path.write_bytes(data)
        logger.info("  KEV: %d bytes", len(data))

        out_path = str(OUT_DIR / f"cisa_kev_{_ts()}.json")
        ok = _run_script("cisa_kev_convert.py", ["--in", str(raw_path), "--out", out_path])
        if not ok:
            return False, None, "cisa_kev_convert.py failed"

        return True, out_path, None
    except Exception as e:
        return False, None, str(e)


# ── EPSS ────────────────────────────────────────────────────────────────────

def refresh_epss() -> tuple[bool, str | None, str | None]:
    """Fetch and convert EPSS scores."""
    _ensure_dirs()
    try:
        logger.info("Fetching EPSS...")
        data = _fetch_url(EPSS_URL, timeout=60)
        csv_data = gzip.decompress(data)
        raw_path = RAW_EPSS / "epss_scores-current.csv"
        raw_path.write_bytes(csv_data)
        logger.info("  EPSS: %d bytes", len(csv_data))

        out_path = str(OUT_DIR / f"epss_{_ts()}.json")
        ok = _run_script("epss_convert.py", ["--in", str(raw_path), "--out", out_path])
        if not ok:
            return False, None, "epss_convert.py failed"

        return True, out_path, None
    except Exception as e:
        return False, None, str(e)


# ── CVE.org (CNA/ADP scores) ───────────────────────────────────────────────

def _score_to_sev(s: float) -> str:
    if s >= 9:
        return "critical"
    if s >= 7:
        return "high"
    if s >= 4:
        return "medium"
    if s > 0:
        return "low"
    return "info"


def _fetch_cveorg_single(cve_id: str):
    try:
        data = json.loads(
            _fetch_url(
                f"{CVEORG_API}/{cve_id}",
                {"Accept": "application/json", "User-Agent": "VulnScan/2.0"},
                15,
            )
        )
        containers = data.get("containers", {})
        cna_score = adp_score = None
        for m in containers.get("cna", {}).get("metrics", []):
            for k in ("cvssV3_1", "cvssV3_0", "cvssV4_0"):
                d = m.get(k)
                if d and d.get("baseScore"):
                    cna_score = float(d["baseScore"])
                    break
            if cna_score:
                break
        for adp in containers.get("adp", []):
            for m in adp.get("metrics", []):
                for k in ("cvssV3_1", "cvssV3_0", "cvssV4_0"):
                    d = m.get(k)
                    if d and d.get("baseScore"):
                        adp_score = float(d["baseScore"])
                        break
                if adp_score:
                    break
            if adp_score:
                break
        if cna_score or adp_score:
            best = max(filter(None, [cna_score, adp_score]))
            return cve_id, {
                "cvss": best,
                "severity": _score_to_sev(best),
                "source": "cna" if not adp_score else "cna+adp" if cna_score else "adp",
                "cna_cvss": cna_score,
                "adp_cvss": adp_score,
            }
    except Exception:
        pass
    return cve_id, None


def refresh_cvedetails(nvd_path: str) -> tuple[bool, str | None, str | None]:
    """Fetch CVE.org CNA/ADP scores for CVEs in the NVD dataset."""
    _ensure_dirs()
    try:
        if not os.path.exists(nvd_path):
            return False, None, f"NVD file not found: {nvd_path}"

        with open(nvd_path) as f:
            cve_ids = [e["cve"] for e in json.load(f) if e.get("cve", "").startswith("CVE-")]

        # Load existing cache
        cache_path = OUT_DIR / "cvedetails_cvss.json"
        existing: dict = {}
        if cache_path.exists():
            try:
                with open(cache_path) as f:
                    existing = json.load(f)
            except Exception:
                pass

        new_ids = [c for c in cve_ids if c not in existing]
        logger.info("CVE.org: %d total CVEs, %d new to fetch", len(cve_ids), len(new_ids))

        if new_ids:
            done = 0
            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
                futures = {pool.submit(_fetch_cveorg_single, c): c for c in new_ids}
                for f in concurrent.futures.as_completed(futures):
                    cve_id, r = f.result()
                    if r:
                        existing[cve_id] = r
                    done += 1
                    if done % 500 == 0 or done == len(new_ids):
                        logger.info("  CVE.org progress: %d/%d (found=%d)", done, len(new_ids), len(existing))

        out_path = str(OUT_DIR / f"cvedetails_cvss_{_ts()}.json")
        with open(out_path, "w") as f:
            json.dump(existing, f, indent=2)

        logger.info("CVE.org cache: %d total -> %s", len(existing), out_path)
        return True, out_path, None

    except Exception as e:
        return False, None, str(e)


# ── Generated datasets ──────────────────────────────────────────────────────

def refresh_cms_cve_map(nvd_path: str) -> tuple[bool, str | None, str | None]:
    """Generate CMS CVE map from NVD data."""
    _ensure_dirs()
    try:
        if not os.path.exists(nvd_path):
            return False, None, f"NVD file not found: {nvd_path}"

        out_path = str(OUT_DIR / f"cms_cve_map_{_ts()}.json")
        ok = _run_script("generate_cms_cve_map.py", ["--nvd", nvd_path, "--out", out_path])
        if not ok:
            return False, None, "generate_cms_cve_map.py failed"

        return True, out_path, None
    except Exception as e:
        return False, None, str(e)


def refresh_compliance_map() -> tuple[bool, str | None, str | None]:
    """Generate compliance framework mapping."""
    _ensure_dirs()
    try:
        out_path = str(OUT_DIR / f"compliance_map_{_ts()}.json")
        ok = _run_script("generate_compliance_map.py", ["--out", out_path])
        if not ok:
            return False, None, "generate_compliance_map.py failed"

        return True, out_path, None
    except Exception as e:
        return False, None, str(e)

