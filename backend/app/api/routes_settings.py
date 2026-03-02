"""
Settings API — manage platform configuration from the UI.
"""
import json
import logging
import os
import re

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_role
from app.core.config import settings
from app.db import models

logger = logging.getLogger("vulnscan.settings")

router = APIRouter(prefix="/settings", tags=["settings"])


# ─── Allowlist ─────────────────────────────────────────────────────────────────

class AllowlistUpdate(BaseModel):
    allowlist: str  # comma-separated


@router.get("/allowlist")
def get_allowlist(user=Depends(require_role("admin", "analyst", "viewer"))):
    """Return current ALLOWLIST as structured data."""
    raw = settings.ALLOWLIST or ""
    entries = [e.strip() for e in raw.split(",") if e.strip()]
    cidrs = [e for e in entries if "/" in e or _is_ip(e)]
    domains = [e for e in entries if e.startswith(".")]
    return {
        "raw": raw,
        "entries": entries,
        "cidrs": cidrs,
        "domains": domains,
        "count": len(entries),
    }


@router.put("/allowlist")
def update_allowlist(
    body: AllowlistUpdate,
    user=Depends(require_role("admin")),
):
    """
    Update the ALLOWLIST in the running process.
    NOTE: This only updates the in-memory value for the current session.
    To persist, the .env file must also be updated (shown in UI).
    """
    new_val = body.allowlist.strip()
    # Validate entries
    entries = [e.strip() for e in new_val.split(",") if e.strip()]
    for entry in entries:
        if not _valid_allowlist_entry(entry):
            raise HTTPException(400, f"Invalid allowlist entry: '{entry}'. Use CIDR (10.0.0.0/8), IP, or domain suffix (.example.com)")

    settings.ALLOWLIST = new_val
    logger.info("Allowlist updated by %s: %s", user.get("sub", "?"), new_val)
    return {
        "ok": True,
        "entries": entries,
        "count": len(entries),
        "note": "Updated for this session. Edit .env to persist across restarts.",
    }


# ─── Platform Info ─────────────────────────────────────────────────────────────

@router.get("/info")
def get_platform_info(user=Depends(require_role("admin", "analyst", "viewer"))):
    """Return platform configuration (non-secret)."""
    return {
        "scan_timeout_seconds": settings.SCAN_TIMEOUT_SECONDS,
        "reports_dir": settings.REPORTS_DIR,
        "neo4j_uri": settings.NEO4J_URI,
        "cors_origins": settings.CORS_ORIGINS,
        "default_workspace": settings.DEFAULT_WORKSPACE,
        "redis_url": _redact_url(settings.REDIS_URL),
        "database_url": _redact_url(settings.DATABASE_URL),
    }


# ─── Workspace Stats ──────────────────────────────────────────────────────────

@router.get("/stats")
def get_workspace_stats(
    user=Depends(require_role("admin", "analyst", "viewer")),
    db: Session = Depends(get_db),
):
    """Return counts for the current workspace."""
    ws = user["ws"]
    jobs_total = db.query(models.ScanJob).filter(models.ScanJob.workspace_id == ws).count()
    jobs_done = db.query(models.ScanJob).filter(models.ScanJob.workspace_id == ws, models.ScanJob.status == "done").count()
    jobs_failed = db.query(models.ScanJob).filter(models.ScanJob.workspace_id == ws, models.ScanJob.status == "failed").count()
    findings = db.query(models.Finding).filter(models.Finding.workspace_id == ws).count()
    profiles = db.query(models.Profile).filter(models.Profile.workspace_id == ws).count()
    datasets = db.query(models.CveDataset).filter(models.CveDataset.workspace_id == ws).count()
    credentials = db.query(models.Credential).filter(models.Credential.workspace_id == ws).count()
    suppressed = db.query(models.SuppressedFinding).filter(models.SuppressedFinding.workspace_id == ws).count()
    return {
        "jobs_total": jobs_total,
        "jobs_done": jobs_done,
        "jobs_failed": jobs_failed,
        "findings": findings,
        "profiles": profiles,
        "datasets": datasets,
        "credentials": credentials,
        "suppressed": suppressed,
    }


# ─── Users (admin only) ───────────────────────────────────────────────────────

@router.get("/users")
def list_users(
    user=Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    ws = user["ws"]
    users = db.query(models.User).filter(models.User.workspace_id == ws).all()
    return [
        {
            "id": u.id,
            "email": u.email,
            "role": u.role,
            "created_at": u.created_at.isoformat() if u.created_at else None,
        }
        for u in users
    ]


# ─── Helpers ───────────────────────────────────────────────────────────────────

def _is_ip(s: str) -> bool:
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", s))


def _valid_allowlist_entry(entry: str) -> bool:
    """Check if an allowlist entry is valid."""
    if not entry:
        return False
    # CIDR notation
    if "/" in entry:
        parts = entry.split("/")
        return len(parts) == 2 and _is_ip(parts[0])
    # Domain suffix
    if entry.startswith("."):
        return len(entry) > 2
    # Bare IP
    if _is_ip(entry):
        return True
    # Bare domain
    if re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9.-]+)?$", entry):
        return True
    return False


def _redact_url(url: str) -> str:
    """Redact password from a connection URL."""
    return re.sub(r"://([^:]+):([^@]+)@", r"://\1:****@", url)
