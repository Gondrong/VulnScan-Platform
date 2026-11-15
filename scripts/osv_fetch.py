#!/usr/bin/env python3
"""
Fetch OSV.dev advisories and convert them to the compact schema consumed by
app.scanner.plugins.cve_packages.match_osv (used by the code scanner's SCA
track and the authenticated package matcher).

Source: OSV.dev per-ecosystem exports
  https://osv-vulnerabilities.storage.googleapis.com/{ECOSYSTEM}/all.zip
Each zip holds one JSON file per advisory in the OSV schema.

Output (JSON array streamed to --out), one record per (advisory, package):
  {
    "id": "GHSA-xxxx",
    "cve": "CVE-2021-1234" | null,
    "ecosystem": "npm",
    "package": "lodash",
    "severity": "high",
    "summary": "...",
    "refs": ["https://..."],
    "ranges": [{"type": "introduced_fixed", "introduced": "0", "fixed": "4.17.21"}]
  }

Only ranges with a concrete fixed version are emitted (match_osv matches
>= introduced < fixed). Advisories with no fix yet are a known gap.

Usage:
  python osv_fetch.py --out /data/cve/osv.json
  python osv_fetch.py --out /data/cve/osv.json --ecosystems npm,PyPI,Go
"""
import argparse
import io
import json
import logging
import sys
import urllib.error
import urllib.parse
import urllib.request
import zipfile

logger = logging.getLogger("osv_fetch")
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

_BASE = "https://osv-vulnerabilities.storage.googleapis.com"
# OSV.dev storage path == ecosystem name we emit (must match sca.py output).
_DEFAULT_ECOSYSTEMS = ["npm", "PyPI", "Maven", "Go", "RubyGems", "Packagist", "crates.io", "NuGet"]
_TIMEOUT = 300


def _download(url: str, timeout: int = _TIMEOUT) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "vulnscan-osv-fetch"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def _cve_of(adv: dict) -> str | None:
    for a in adv.get("aliases", []) or []:
        if isinstance(a, str) and a.upper().startswith("CVE-"):
            return a
    if str(adv.get("id", "")).upper().startswith("CVE-"):
        return adv["id"]
    return None


def _severity_of(adv: dict, affected: dict) -> str:
    # Prefer a database_specific label on the affected entry, then advisory-level
    ds = (affected.get("database_specific") or {})
    label = ds.get("severity") or (adv.get("database_specific") or {}).get("severity")
    if isinstance(label, str) and label.strip():
        s = label.strip().lower()
        if s in ("critical", "high", "medium", "moderate", "low"):
            return "medium" if s == "moderate" else s
    # Fall back to CVSS score → band
    for sev in adv.get("severity", []) or []:
        score = sev.get("score", "")
        val = _cvss_base(score)
        if val is not None:
            if val >= 9.0:
                return "critical"
            if val >= 7.0:
                return "high"
            if val >= 4.0:
                return "medium"
            return "low"
    return "medium"


def _cvss_base(score: str):
    # score may be a CVSS vector or a bare number
    try:
        return float(score)
    except (TypeError, ValueError):
        return None


def _ranges_of(affected: dict) -> list[dict]:
    out = []
    for r in affected.get("ranges", []) or []:
        introduced = "0"
        for ev in r.get("events", []) or []:
            if "introduced" in ev:
                introduced = ev["introduced"]
            elif "fixed" in ev and ev["fixed"]:
                out.append({"type": "introduced_fixed",
                            "introduced": introduced, "fixed": ev["fixed"]})
                introduced = "0"
    return out


def _records_for(adv: dict):
    cve = _cve_of(adv)
    summary = adv.get("summary") or (adv.get("details") or "")[:300]
    refs = [x.get("url") for x in (adv.get("references") or []) if x.get("url")][:8]
    for affected in adv.get("affected", []) or []:
        pkg = (affected.get("package") or {})
        name = pkg.get("name")
        eco = pkg.get("ecosystem")
        if not name or not eco:
            continue
        # OSV Maven names are "group:artifact"; keep as-is (sca.py pom not yet parsed)
        ranges = _ranges_of(affected)
        if not ranges:
            continue
        yield {
            "id": adv.get("id"),
            "cve": cve,
            "ecosystem": eco.split(":")[0] if eco.startswith("Maven") else eco,
            "package": name,
            "severity": _severity_of(adv, affected),
            "summary": summary,
            "refs": refs,
            "ranges": ranges,
        }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--ecosystems", default=",".join(_DEFAULT_ECOSYSTEMS))
    ap.add_argument("--timeout", type=int, default=_TIMEOUT)
    args = ap.parse_args()

    ecosystems = [e.strip() for e in args.ecosystems.split(",") if e.strip()]
    total_recs = 0
    total_adv = 0
    errors = []

    with open(args.out, "w", encoding="utf-8") as fout:
        fout.write("[")
        first = True
        for eco in ecosystems:
            url = f"{_BASE}/{urllib.parse.quote(eco)}/all.zip"
            try:
                blob = _download(url, args.timeout)
            except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as e:
                logger.warning("%s: download failed: %s", eco, e)
                errors.append(f"{eco}: {e}")
                continue
            try:
                zf = zipfile.ZipFile(io.BytesIO(blob))
            except zipfile.BadZipFile as e:
                logger.warning("%s: bad zip: %s", eco, e)
                errors.append(f"{eco}: bad zip")
                continue
            eco_recs = 0
            for member in zf.namelist():
                if not member.endswith(".json"):
                    continue
                try:
                    adv = json.loads(zf.read(member))
                except Exception:  # noqa: BLE001
                    continue
                total_adv += 1
                for rec in _records_for(adv):
                    if not first:
                        fout.write(",")
                    fout.write(json.dumps(rec, ensure_ascii=False))
                    first = False
                    eco_recs += 1
                    total_recs += 1
            logger.info("%s: %d advisories → %d package records", eco, len(zf.namelist()), eco_recs)
        fout.write("]")

    logger.info("OSV: %d advisories, %d package records → %s", total_adv, total_recs, args.out)
    if total_recs == 0:
        logger.error("No records produced (errors: %s)", "; ".join(errors) or "none")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
