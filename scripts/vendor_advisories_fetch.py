#!/usr/bin/env python3
"""
Fetch vendor security advisories and map them to CVE IDs.

Sources:
  - Ubuntu Security Notices (USN) via ubuntu.com API
  - Debian Security Tracker via security-tracker.debian.org JSON
  - Red Hat Security Data API
  - GCP Security Bulletins via Atom feed

Output: JSON dict keyed by CVE-ID, each value is a list of advisory objects:
  {
    "CVE-2024-1234": [
      {"vendor": "ubuntu", "id": "USN-6543-1", "url": "...", "title": "...", "affected_versions": ["22.04"]},
      ...
    ]
  }

Usage:
  python vendor_advisories_fetch.py --out /data/cve/vendor_advisories.json
  python vendor_advisories_fetch.py --out /data/cve/vendor_advisories.json --sources ubuntu,debian
"""
import argparse
import json
import logging
import sys
import time
import urllib.error
import urllib.request
from typing import Any

logger = logging.getLogger("vendor_advisories")
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

_TIMEOUT = 30
_MAX_RETRIES = 3


def _fetch_json(url: str, timeout: int = _TIMEOUT) -> Any:
    """Fetch URL with retries and backoff."""
    for attempt in range(1, _MAX_RETRIES + 1):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "VulnScan-Platform/2.0"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read())
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as e:
            if attempt == _MAX_RETRIES:
                raise
            wait = 2 ** attempt
            logger.warning("  Retry %d/%d for %s: %s (waiting %ds)", attempt, _MAX_RETRIES, url, e, wait)
            time.sleep(wait)


def _fetch_raw(url: str, timeout: int = _TIMEOUT) -> bytes:
    """Fetch raw bytes with retries."""
    for attempt in range(1, _MAX_RETRIES + 1):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "VulnScan-Platform/2.0"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read()
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as e:
            if attempt == _MAX_RETRIES:
                raise
            wait = 2 ** attempt
            logger.warning("  Retry %d/%d for %s: %s (waiting %ds)", attempt, _MAX_RETRIES, url, e, wait)
            time.sleep(wait)


# ── Ubuntu USN ──────────────────────────────────────────────────────────────

def fetch_ubuntu(result: dict[str, list]) -> int:
    """Fetch Ubuntu Security Notices and map CVE -> advisory."""
    logger.info("Ubuntu: fetching security notices...")
    base = "https://ubuntu.com/security/notices.json"
    count = 0
    offset = 0
    limit = 20  # Ubuntu API rejects limit > ~20
    max_pages = 100  # 20 * 100 = 2000 most recent notices

    for page in range(max_pages):
        url = f"{base}?limit={limit}&offset={offset}"
        try:
            data = _fetch_json(url, timeout=45)
        except Exception as e:
            logger.warning("Ubuntu: failed at offset %d: %s", offset, e)
            break

        notices = data.get("notices") or []
        if not notices:
            break

        for notice in notices:
            usn_id = notice.get("id") or ""
            title = notice.get("title") or ""
            cves = notice.get("cves") or notice.get("cves_ids") or []
            # Extract affected release names
            releases = []
            for rel in (notice.get("releases") or []):
                if isinstance(rel, dict):
                    ver = rel.get("version", "")
                    tag = rel.get("support_tag", "")
                    releases.append(f"{ver} {tag}".strip() if ver else rel.get("codename", ""))
                elif isinstance(rel, str):
                    releases.append(rel)

            for cve_obj in cves:
                cve_id = ""
                if isinstance(cve_obj, str):
                    cve_id = cve_obj.strip().upper()
                elif isinstance(cve_obj, dict):
                    cve_id = (cve_obj.get("id") or cve_obj.get("cve") or "").strip().upper()
                if not cve_id.startswith("CVE-"):
                    continue

                entry = {
                    "vendor": "ubuntu",
                    "id": usn_id,
                    "url": f"https://ubuntu.com/security/notices/{usn_id}",
                    "title": title[:200],
                }
                if releases:
                    entry["affected_versions"] = releases[:10]

                result.setdefault(cve_id, []).append(entry)
                count += 1

        total = data.get("total_results") or 0
        offset += limit
        if offset >= total or offset >= limit * max_pages:
            break

        time.sleep(0.5)  # Rate limit

    logger.info("Ubuntu: %d advisory mappings collected", count)
    return count


# ── Debian Security Tracker ─────────────────────────────────────────────────

def fetch_debian(result: dict[str, list]) -> int:
    """Fetch Debian Security Tracker JSON and map CVE -> advisory."""
    logger.info("Debian: fetching security tracker data...")
    url = "https://security-tracker.debian.org/tracker/data/json"
    count = 0

    try:
        data = _fetch_json(url, timeout=60)
    except Exception as e:
        logger.error("Debian: failed to fetch: %s", e)
        return 0

    if not isinstance(data, dict):
        logger.error("Debian: unexpected data format")
        return 0

    # Structure: {package_name: {CVE-ID: {releases: {release: {status, fixed_version}}}}}
    for pkg_name, cves in data.items():
        if not isinstance(cves, dict):
            continue
        for cve_id, info in cves.items():
            cve_id = cve_id.strip().upper()
            if not cve_id.startswith("CVE-"):
                continue
            if not isinstance(info, dict):
                continue

            releases = info.get("releases") or {}
            affected = []
            for rel_name, rel_info in releases.items():
                status = (rel_info.get("status") or "") if isinstance(rel_info, dict) else ""
                if status in ("resolved", "open"):
                    affected.append(rel_name)

            if not affected:
                continue

            entry = {
                "vendor": "debian",
                "id": f"debian/{pkg_name}",
                "url": f"https://security-tracker.debian.org/tracker/{cve_id}",
                "title": f"{pkg_name} security update",
                "affected_versions": affected[:10],
            }

            # Check for DSA/DLA references
            dsa_list = info.get("debianbug") or ""

            result.setdefault(cve_id, []).append(entry)
            count += 1

    logger.info("Debian: %d advisory mappings collected", count)
    return count


# ── Red Hat Security Data ────────────────────────────────────────────────────

def fetch_redhat(result: dict[str, list]) -> int:
    """Fetch Red Hat CVE data and map CVE -> RHSA advisories."""
    logger.info("Red Hat: fetching security data...")
    base = "https://access.redhat.com/hydra/rest/securitydata/cve.json"
    count = 0
    page = 1
    per_page = 500
    max_pages = 20

    for _ in range(max_pages):
        url = f"{base}?per_page={per_page}&page={page}"
        try:
            data = _fetch_json(url, timeout=45)
        except Exception as e:
            logger.warning("Red Hat: failed at page %d: %s", page, e)
            break

        if not isinstance(data, list) or not data:
            break

        for item in data:
            cve_id = (item.get("CVE") or "").strip().upper()
            if not cve_id.startswith("CVE-"):
                continue

            severity = item.get("severity") or ""
            advisories = item.get("advisories") or []

            for adv in advisories:
                rhsa_id = adv if isinstance(adv, str) else (adv.get("rhsa_id") or "")
                if not rhsa_id:
                    continue

                entry = {
                    "vendor": "redhat",
                    "id": rhsa_id,
                    "url": f"https://access.redhat.com/errata/{rhsa_id}",
                    "title": f"Red Hat Security Advisory {rhsa_id}",
                }
                if severity:
                    entry["severity"] = severity

                result.setdefault(cve_id, []).append(entry)
                count += 1

        if len(data) < per_page:
            break
        page += 1
        time.sleep(0.5)

    logger.info("Red Hat: %d advisory mappings collected", count)
    return count


# ── GCP Security Bulletins ───────────────────────────────────────────────────

def fetch_gcp(result: dict[str, list]) -> int:
    """Fetch GCP Security Bulletins from Atom feed."""
    import re
    import xml.etree.ElementTree as ET

    logger.info("GCP: fetching security bulletins feed...")
    url = "https://cloud.google.com/feeds/google-cloud-security-bulletins.xml"
    count = 0

    try:
        raw = _fetch_raw(url, timeout=30)
    except Exception as e:
        logger.error("GCP: failed to fetch feed: %s", e)
        return 0

    try:
        root = ET.fromstring(raw)
    except ET.ParseError as e:
        logger.error("GCP: failed to parse XML: %s", e)
        return 0

    ns = {"atom": "http://www.w3.org/2005/Atom"}
    cve_pattern = re.compile(r"CVE-\d{4}-\d{4,}")

    for entry in root.findall(".//atom:entry", ns):
        title_el = entry.find("atom:title", ns)
        link_el = entry.find("atom:link", ns)
        content_el = entry.find("atom:content", ns)

        title = title_el.text.strip() if title_el is not None and title_el.text else ""
        link = link_el.get("href", "") if link_el is not None else ""
        content = content_el.text or "" if content_el is not None else ""

        # Extract CVE-IDs from title and content
        cve_ids = set(cve_pattern.findall(title + " " + content))
        if not cve_ids:
            continue

        for cve_id in cve_ids:
            cve_id = cve_id.upper()
            entry_obj = {
                "vendor": "gcp",
                "id": title[:80] if title else "GCP Bulletin",
                "url": link,
                "title": title[:200],
            }
            result.setdefault(cve_id, []).append(entry_obj)
            count += 1

    logger.info("GCP: %d advisory mappings collected", count)
    return count


# ── Main ─────────────────────────────────────────────────────────────────────

_SOURCES = {
    "ubuntu": fetch_ubuntu,
    "debian": fetch_debian,
    "redhat": fetch_redhat,
    "gcp": fetch_gcp,
}


def main():
    ap = argparse.ArgumentParser(description="Fetch vendor security advisories mapped to CVE IDs")
    ap.add_argument("--out", required=True, help="Output JSON file path")
    ap.add_argument("--sources", default="", help="Comma-separated vendor list (default: all)")
    args = ap.parse_args()

    sources = [s.strip() for s in args.sources.split(",") if s.strip()] if args.sources else list(_SOURCES.keys())
    invalid = set(sources) - set(_SOURCES)
    if invalid:
        print(f"Unknown sources: {invalid}. Valid: {list(_SOURCES.keys())}", file=sys.stderr)
        sys.exit(1)

    result: dict[str, list] = {}
    success_count = 0
    fail_count = 0

    for source in sources:
        try:
            n = _SOURCES[source](result)
            if n > 0:
                success_count += 1
            else:
                logger.warning("Source '%s' returned 0 results", source)
        except Exception as e:
            logger.error("Source '%s' failed: %s", source, e)
            fail_count += 1

    # Deduplicate advisories per CVE (by vendor+id)
    for cve_id in result:
        seen = set()
        deduped = []
        for adv in result[cve_id]:
            key = (adv.get("vendor"), adv.get("id"))
            if key not in seen:
                seen.add(key)
                deduped.append(adv)
        result[cve_id] = deduped

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False)

    total_cves = len(result)
    total_advs = sum(len(v) for v in result.values())
    print(f"Vendor advisories: {total_cves} CVEs, {total_advs} advisory mappings "
          f"({success_count} sources OK, {fail_count} failed) -> {args.out}")

    # Exit with error only if ALL sources failed
    if success_count == 0 and fail_count > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
