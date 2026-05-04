"""
Threat Intel API — fused NVD + EPSS + CISA KEV per CVE.

Endpoints:
  GET /threat-intel/cves          — paginated, filterable, sortable list
  GET /threat-intel/cves/{cve_id} — single-CVE detail
  GET /threat-intel/stats         — summary counters (used for dashboard tiles)
  POST /threat-intel/refresh      — explicit cache invalidation (admin only)
"""
import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_role
from app.threat_intel import aggregator

logger = logging.getLogger("vulnscan.api.threat_intel")
router = APIRouter(prefix="/threat-intel", tags=["threat-intel"])


@router.get("/stats")
def stats(
    user=Depends(require_role("admin", "analyst", "viewer")),
    db: Session = Depends(get_db),
):
    """Summary counters for the Threat Intel page header / dashboard tiles."""
    return aggregator.stats(db, user["ws"])


@router.get("/cves")
def list_cves(
    q: str = Query("", description="Free-text search (CVE-ID / vendor / product / summary)"),
    severity: Optional[str] = Query(None, description="Comma-separated: critical,high,medium,low"),
    kev_only: bool = Query(False),
    ransomware_only: bool = Query(False),
    min_epss: Optional[float] = Query(None, ge=0.0, le=1.0),
    min_cvss: Optional[float] = Query(None, ge=0.0, le=10.0),
    sort: str = Query("threat_score", description="threat_score | cvss | epss | kev_due | kev_added"),
    order: str = Query("desc", description="asc | desc"),
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    user=Depends(require_role("admin", "analyst", "viewer")),
    db: Session = Depends(get_db),
):
    sev_list = [s.strip() for s in (severity or "").split(",") if s.strip()] or None
    return aggregator.query(
        db, user["ws"],
        q=q, severity=sev_list,
        kev_only=kev_only, ransomware_only=ransomware_only,
        min_epss=min_epss, min_cvss=min_cvss,
        sort=sort, order=order,
        page=page, per_page=per_page,
    )


@router.get("/cves/{cve_id}")
def get_cve(
    cve_id: str,
    user=Depends(require_role("admin", "analyst", "viewer")),
    db: Session = Depends(get_db),
):
    rec = aggregator.detail(db, user["ws"], cve_id)
    if not rec:
        raise HTTPException(404, f"CVE not found in Threat Intel cache: {cve_id}")
    return rec


@router.post("/refresh")
def refresh_cache(
    user=Depends(require_role("admin", "analyst")),
):
    """Manually invalidate the Threat Intel cache for the workspace."""
    aggregator.invalidate(user["ws"])
    logger.info("Threat Intel cache invalidated: ws=%s actor=%s", user["ws"], user.get("sub", "?"))
    return {"ok": True, "invalidated": user["ws"]}
