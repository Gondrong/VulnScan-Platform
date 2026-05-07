"""
Threat Intel aggregator.

Merges per-CVE data from the workspace's enabled NVD, EPSS, and CISA KEV
datasets into a single dict keyed by CVE-ID. Cached per workspace with a
5-minute TTL; the cache is also invalidated explicitly when dataset
refresh completes.

Memory note: NVD ships ~200K CVEs at roughly 1 KB per record after our
flatten step, so the cache is ~200 MB resident per workspace. Single-
workspace installs (the common case) are fine. Multi-tenant deployments
should keep an eye on this and prefer the SQLite index in the v2 plan.
"""
from __future__ import annotations

import json
import logging
import os
import threading
import time
from datetime import date, datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from app.db import models

logger = logging.getLogger("vulnscan.threat_intel")

_CACHE_TTL_SECONDS = 300.0


# ─── Per-workspace in-memory cache ──────────────────────────────────────────

class _CacheEntry:
    __slots__ = ("ts", "merged", "stats", "datasets_loaded")

    def __init__(self) -> None:
        self.ts: float = 0.0
        self.merged: dict[str, dict[str, Any]] = {}
        self.stats: dict[str, Any] = {}
        self.datasets_loaded: list[str] = []


_cache: dict[int, _CacheEntry] = {}
_lock = threading.Lock()


def invalidate(workspace_id: int | None = None) -> None:
    """Drop the cache for one workspace, or all of them when called with None."""
    with _lock:
        if workspace_id is None:
            _cache.clear()
        else:
            _cache.pop(workspace_id, None)


# ─── Loaders for each dataset kind ──────────────────────────────────────────

def _load_dataset_file(path: str) -> Any:
    if not path or not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        logger.warning("Threat Intel: could not load %s: %s", path, e)
        return None


def _enabled_path(db: Session, ws_id: int, kind: str) -> str | None:
    ds = (
        db.query(models.CveDataset)
        .filter(
            models.CveDataset.workspace_id == ws_id,
            models.CveDataset.kind == kind,
            models.CveDataset.enabled == True,  # noqa: E712
        )
        .order_by(models.CveDataset.id.desc())
        .first()
    )
    return ds.path if ds else None


def _normalise_nvd(raw: Any) -> list[dict]:
    if isinstance(raw, list):
        return raw
    if isinstance(raw, dict) and "vulnerabilities" in raw:
        return raw["vulnerabilities"]
    return []


# ─── Build the merged map ───────────────────────────────────────────────────

def _vendor_product_from_cpe(cpe23: str) -> tuple[str, str]:
    """Best-effort vendor/product extraction from a CPE 2.3 URI."""
    parts = (cpe23 or "").split(":")
    if len(parts) >= 5:
        vendor = (parts[3] or "").replace("_", " ").strip()
        product = (parts[4] or "").replace("_", " ").strip()
        return vendor, product
    return "", ""


def _parse_iso_date(s: str) -> date | None:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).date()
    except Exception:
        try:
            return datetime.strptime(s[:10], "%Y-%m-%d").date()
        except Exception:
            return None


def _compute_threat_score(rec: dict) -> float:
    """
    Composite threat score, 0–100.

    Weights:
      40% CVSS, 35% EPSS percentile, 15% KEV (with +3 ransomware kicker),
      10% recency bonus on KEV add date.
    """
    cvss = float(rec.get("cvss") or 0.0)
    epss_p = float(rec.get("epss_percentile") or 0.0)
    kev = bool(rec.get("kev"))
    ransom = bool(rec.get("ransomware"))

    score = (cvss / 10.0) * 40.0 + epss_p * 35.0
    if kev:
        score += 12.0
    if ransom:
        score += 3.0

    added = rec.get("kev_added")
    if added:
        d = _parse_iso_date(added)
        if d:
            days = (date.today() - d).days
            if days <= 7:
                score += 10.0
            elif days <= 30:
                score += 7.0
            elif days <= 90:
                score += 4.0

    return round(min(max(score, 0.0), 100.0), 1)


def _build_merged(db: Session, ws_id: int) -> _CacheEntry:
    entry = _CacheEntry()

    nvd_path = _enabled_path(db, ws_id, "nvd_cpe_cve")
    kev_path = _enabled_path(db, ws_id, "cisa_kev")
    epss_path = _enabled_path(db, ws_id, "epss")

    nvd_raw = _load_dataset_file(nvd_path) if nvd_path else None
    kev_raw = _load_dataset_file(kev_path) if kev_path else None
    epss_raw = _load_dataset_file(epss_path) if epss_path else None

    merged: dict[str, dict[str, Any]] = {}
    loaded: list[str] = []

    # NVD — primary source for CVSS, summary, severity, CPE matches
    if nvd_raw:
        loaded.append("nvd")
        for row in _normalise_nvd(nvd_raw):
            cve_id = (row.get("cve") or row.get("id") or "").strip().upper()
            if not cve_id.startswith("CVE-"):
                continue
            matches = row.get("matches") or []
            vendor, product = ("", "")
            if matches:
                vendor, product = _vendor_product_from_cpe(matches[0].get("cpe23", ""))

            merged[cve_id] = {
                "cve": cve_id,
                "summary": row.get("summary") or "",
                "cvss": row.get("cvss"),
                "severity": (row.get("severity") or "").lower(),
                "vendor": vendor,
                "product": product,
                "matches": matches[:50],
                "refs": row.get("refs") or [],
                "vendor_advisories": row.get("vendor_advisories") or {},
                "epss": None,
                "epss_percentile": None,
                "kev": False,
                "kev_added": None,
                "kev_due": None,
                "ransomware": False,
                "kev_notes": "",
            }

    # CISA KEV — overlays exploitation status + ransomware flag
    if kev_raw and isinstance(kev_raw, list):
        loaded.append("kev")
        for row in kev_raw:
            cve_id = (row.get("cve") or row.get("cveID") or "").strip().upper()
            if not cve_id.startswith("CVE-"):
                continue
            rec = merged.get(cve_id)
            if rec is None:
                # KEV-only entries (no NVD match yet) — minimal record
                rec = {
                    "cve": cve_id,
                    "summary": row.get("notes") or "",
                    "cvss": None,
                    "severity": "",
                    "vendor": row.get("vendorProject") or "",
                    "product": row.get("product") or "",
                    "matches": [],
                    "refs": row.get("refs") or [],
                    "epss": None,
                    "epss_percentile": None,
                }
                merged[cve_id] = rec
            else:
                # Prefer KEV's vendor/product when present (more accurate than CPE-derived)
                if row.get("vendorProject"):
                    rec["vendor"] = row["vendorProject"]
                if row.get("product"):
                    rec["product"] = row["product"]

            rec["kev"] = True
            rec["kev_added"] = row.get("dateAdded") or None
            rec["kev_due"] = row.get("dueDate") or None
            rec["ransomware"] = (row.get("knownRansomwareCampaignUse") or "").strip().lower() == "known"
            rec["kev_notes"] = row.get("notes") or ""

    # EPSS — overlays exploitation probability
    if epss_raw and isinstance(epss_raw, list):
        loaded.append("epss")
        for row in epss_raw:
            cve_id = (row.get("cve") or "").strip().upper()
            if not cve_id.startswith("CVE-"):
                continue
            rec = merged.get(cve_id)
            if rec is None:
                continue  # don't synthesise records from EPSS alone
            try:
                rec["epss"] = float(row.get("epss") or 0.0)
                rec["epss_percentile"] = float(row.get("percentile") or 0.0)
            except (TypeError, ValueError):
                pass

    # Vendor advisories (external dataset) — overlays additional vendor references
    va_path = _enabled_path(db, ws_id, "vendor_advisories")
    va_raw = _load_dataset_file(va_path) if va_path else None

    if va_raw and isinstance(va_raw, dict):
        loaded.append("vendor_advisories")
        for cve_id_raw, advisories in va_raw.items():
            cve_id = cve_id_raw.strip().upper()
            rec = merged.get(cve_id)
            if rec is None:
                continue
            if not isinstance(advisories, list):
                continue
            existing_va = rec.get("vendor_advisories") or {}
            for adv in advisories:
                vendor = adv.get("vendor", "unknown")
                if vendor not in existing_va:
                    existing_va[vendor] = []
                # Deduplicate by URL
                existing_urls = {a.get("url") for a in existing_va[vendor]}
                if adv.get("url") and adv["url"] not in existing_urls:
                    existing_va[vendor].append(adv)
            rec["vendor_advisories"] = existing_va

    # Final pass — compute threat scores
    for rec in merged.values():
        rec["threat_score"] = _compute_threat_score(rec)

    # Build summary stats
    today = date.today()
    kev_count = 0
    kev_due_7d = 0
    new_kev_7d = 0
    ransom_count = 0
    high_epss = 0
    critical_count = 0
    high_count = 0
    vendor_adv_vendors: set[str] = set()
    vendor_adv_cve_count = 0

    for rec in merged.values():
        if rec.get("kev"):
            kev_count += 1
            d_due = _parse_iso_date(rec.get("kev_due") or "")
            if d_due and 0 <= (d_due - today).days <= 7:
                kev_due_7d += 1
            d_added = _parse_iso_date(rec.get("kev_added") or "")
            if d_added and 0 <= (today - d_added).days <= 7:
                new_kev_7d += 1
        if rec.get("ransomware"):
            ransom_count += 1
        epss = rec.get("epss")
        if isinstance(epss, (int, float)) and epss >= 0.5:
            high_epss += 1
        sev = rec.get("severity", "")
        if sev == "critical":
            critical_count += 1
        elif sev == "high":
            high_count += 1
        va = rec.get("vendor_advisories")
        if va:
            vendor_adv_cve_count += 1
            vendor_adv_vendors.update(va.keys())

    entry.merged = merged
    entry.stats = {
        "total_cves": len(merged),
        "kev_count": kev_count,
        "kev_due_within_7d": kev_due_7d,
        "ransomware_count": ransom_count,
        "new_kev_7d": new_kev_7d,
        "high_epss_count": high_epss,
        "critical_count": critical_count,
        "high_count": high_count,
        "datasets_loaded": loaded,
        "vendor_advisory_vendors": sorted(vendor_adv_vendors),
        "vendor_advisory_cve_count": vendor_adv_cve_count,
    }
    entry.datasets_loaded = loaded
    entry.ts = time.time()

    logger.info(
        "Threat Intel: ws=%d built — %d CVEs (NVD=%s, KEV=%s, EPSS=%s, kev_count=%d, ransom=%d)",
        ws_id, len(merged), nvd_path is not None, kev_path is not None,
        epss_path is not None, kev_count, ransom_count,
    )
    return entry


def _get_or_build(db: Session, ws_id: int) -> _CacheEntry:
    with _lock:
        entry = _cache.get(ws_id)
        if entry and (time.time() - entry.ts) < _CACHE_TTL_SECONDS:
            return entry

    # Build outside the lock — first request takes 5–10 s on a full NVD dump
    built = _build_merged(db, ws_id)
    with _lock:
        _cache[ws_id] = built
    return built


# ─── Public API: query, detail, stats ───────────────────────────────────────

_VALID_SORTS = {"threat_score", "cvss", "epss", "kev_due", "kev_added", "published"}


def query(
    db: Session,
    ws_id: int,
    *,
    q: str = "",
    severity: list[str] | None = None,
    kev_only: bool = False,
    ransomware_only: bool = False,
    min_epss: float | None = None,
    min_cvss: float | None = None,
    sort: str = "threat_score",
    order: str = "desc",
    page: int = 1,
    per_page: int = 50,
) -> dict[str, Any]:
    entry = _get_or_build(db, ws_id)
    rows = list(entry.merged.values())

    # Filters
    ql = (q or "").strip().lower()
    sev_set = {s.lower() for s in (severity or []) if s}

    def _keep(r: dict) -> bool:
        if ql:
            blob = " ".join(str(r.get(k) or "") for k in ("cve", "summary", "vendor", "product")).lower()
            if ql not in blob:
                return False
        if sev_set and (r.get("severity") or "").lower() not in sev_set:
            return False
        if kev_only and not r.get("kev"):
            return False
        if ransomware_only and not r.get("ransomware"):
            return False
        if min_epss is not None and (r.get("epss") or 0.0) < min_epss:
            return False
        if min_cvss is not None and (r.get("cvss") or 0.0) < min_cvss:
            return False
        return True

    rows = [r for r in rows if _keep(r)]

    # Sort
    if sort not in _VALID_SORTS:
        sort = "threat_score"
    reverse = (order or "desc").lower() != "asc"

    def _key(r: dict):
        if sort == "kev_due":
            d = _parse_iso_date(r.get("kev_due") or "")
            # Sort missing dates to the end regardless of order
            return (1 if d is None else 0, d or date(1970, 1, 1))
        if sort == "kev_added":
            d = _parse_iso_date(r.get("kev_added") or "")
            return (1 if d is None else 0, d or date(1970, 1, 1))
        if sort == "cvss":
            return r.get("cvss") or 0.0
        if sort == "epss":
            return r.get("epss") or 0.0
        return r.get("threat_score") or 0.0

    rows.sort(key=_key, reverse=reverse)

    total = len(rows)
    per_page = max(1, min(per_page, 200))
    page = max(1, page)
    start = (page - 1) * per_page
    end = start + per_page
    page_rows = rows[start:end]

    return {
        "total": total,
        "page": page,
        "per_page": per_page,
        "total_pages": max(1, -(-total // per_page)),
        "cves": [_summarise(r) for r in page_rows],
    }


def detail(db: Session, ws_id: int, cve_id: str) -> dict[str, Any] | None:
    entry = _get_or_build(db, ws_id)
    rec = entry.merged.get((cve_id or "").strip().upper())
    if not rec:
        return None
    out = dict(rec)
    # Full record — includes summary, matches, kev_notes, refs (already there)
    return out


def stats(db: Session, ws_id: int) -> dict[str, Any]:
    entry = _get_or_build(db, ws_id)
    return dict(entry.stats)


def _summarise(rec: dict) -> dict:
    """Compact row used in list responses."""
    return {
        "cve":               rec.get("cve"),
        "summary":           (rec.get("summary") or "")[:240],
        "cvss":              rec.get("cvss"),
        "severity":          rec.get("severity"),
        "vendor":            rec.get("vendor"),
        "product":           rec.get("product"),
        "epss":              rec.get("epss"),
        "epss_percentile":   rec.get("epss_percentile"),
        "kev":               rec.get("kev"),
        "kev_added":         rec.get("kev_added"),
        "kev_due":           rec.get("kev_due"),
        "ransomware":        rec.get("ransomware"),
        "threat_score":      rec.get("threat_score"),
    }
