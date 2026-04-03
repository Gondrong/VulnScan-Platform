"""
Settings API — manage platform configuration from the UI.
"""
import hashlib
import json
import logging
import os
import re
from datetime import datetime, timezone

import redis
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


class UserCreate(BaseModel):
    email: str
    password: str
    role: str = "analyst"


@router.post("/users")
def create_user(
    body: UserCreate,
    user=Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    ws = user["ws"]
    if not body.email or not body.password:
        raise HTTPException(400, "Email and password required")
    if body.role not in ("admin", "analyst", "viewer"):
        raise HTTPException(400, "Role must be admin, analyst, or viewer")

    existing = db.query(models.User).filter(
        models.User.workspace_id == ws,
        models.User.email == body.email,
    ).first()
    if existing:
        raise HTTPException(409, f"User '{body.email}' already exists")

    pw_hash = hashlib.sha256(body.password.encode("utf-8")).hexdigest()
    new_user = models.User(
        workspace_id=ws,
        email=body.email,
        password_hash=pw_hash,
        role=body.role,
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    logger.info("User created: %s (role=%s) by %s", body.email, body.role, user.get("sub", "?"))
    return {"id": new_user.id, "email": new_user.email, "role": new_user.role}


@router.delete("/users/{user_id}")
def delete_user(
    user_id: int,
    user=Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    ws = user["ws"]
    target = db.query(models.User).filter(
        models.User.id == user_id,
        models.User.workspace_id == ws,
    ).first()
    if not target:
        raise HTTPException(404, "User not found")
    if target.email == user.get("sub"):
        raise HTTPException(400, "Cannot delete your own account")
    db.delete(target)
    db.commit()
    logger.info("User deleted: #%d %s by %s", user_id, target.email, user.get("sub", "?"))
    return {"ok": True}


# ─── Integration Tests ────────────────────────────────────────────────────────

class IntegrationTest(BaseModel):
    type: str
    url: str | None = None
    host: str | None = None
    port: str | None = None
    from_addr: str | None = None
    password: str | None = None
    to: str | None = None


@router.post("/integrations/test")
def test_integration(
    body: IntegrationTest,
    user=Depends(require_role("admin")),
):
    """Test an integration (Slack, Email, Webhook). Best-effort — returns success or error."""
    if body.type == "slack":
        if not body.url or "hooks.slack" not in body.url:
            raise HTTPException(400, "Invalid Slack webhook URL")
        # In production, you'd POST to the URL. For now, validate format.
        logger.info("Slack test by %s: %s", user.get("sub", "?"), body.url[:60])
        return {"ok": True, "message": "Slack webhook URL validated. Deliver test message in production."}

    elif body.type == "email":
        if not body.host or not body.to:
            raise HTTPException(400, "SMTP host and recipient required")
        logger.info("Email test by %s: %s -> %s", user.get("sub", "?"), body.host, body.to)
        return {"ok": True, "message": f"SMTP config validated: {body.host}:{body.port or 587} → {body.to}"}

    elif body.type == "webhook":
        if not body.url or not body.url.startswith("http"):
            raise HTTPException(400, "Invalid webhook URL")
        logger.info("Webhook test by %s: %s", user.get("sub", "?"), body.url[:60])
        return {"ok": True, "message": "Webhook URL validated."}

    raise HTTPException(400, f"Unknown integration type: {body.type}")


# ─── Platform Update ─────────────────────────────────────────────────────────

def _redis_conn():
    return redis.from_url(settings.REDIS_URL, decode_responses=True)


@router.get("/update/check")
def check_for_update(user=Depends(require_role("admin", "analyst", "viewer"))):
    """Check GitHub Releases for a newer version. Cached for 24 hours."""
    r = _redis_conn()
    cache_key = "update_check_cache"

    # Return cached result if available
    cached = r.get(cache_key)
    if cached:
        try:
            return json.loads(cached)
        except Exception:
            pass

    # Fetch latest release from GitHub
    import urllib.request
    current = settings.PLATFORM_VERSION
    repo = settings.GITHUB_REPO

    try:
        url = f"https://api.github.com/repos/{repo}/releases/latest"
        req = urllib.request.Request(url, headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "VulnScan-Platform",
        })
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
    except Exception as e:
        return {
            "available": False,
            "current": current,
            "latest": current,
            "error": f"Could not reach GitHub: {str(e)[:200]}",
        }

    latest_tag = data.get("tag_name", "")
    latest_ver = latest_tag.lstrip("vV")
    release_name = data.get("name", "")
    release_body = data.get("body", "")[:500]
    published_at = data.get("published_at", "")

    # Compare versions (simple string comparison works for semver)
    def _ver_tuple(v):
        try:
            return tuple(int(x) for x in v.split("."))
        except Exception:
            return (0, 0, 0)

    available = _ver_tuple(latest_ver) > _ver_tuple(current)

    result = {
        "available": available,
        "current": current,
        "latest": latest_ver,
        "tag": latest_tag,
        "release_name": release_name,
        "release_notes": release_body,
        "published_at": published_at,
        "repo": repo,
    }

    # Cache for 24 hours
    r.setex(cache_key, 86400, json.dumps(result))

    return result


@router.post("/update/trigger")
def trigger_update(user=Depends(require_role("admin"))):
    """Trigger a platform update. Writes a trigger file that the host updater picks up."""
    trigger_path = "/data/update-trigger.json"
    result_path = "/data/update-result.json"

    # Check if update is already in progress
    if os.path.exists(trigger_path):
        raise HTTPException(409, "Update already triggered — waiting for host updater to process")

    if os.path.exists(result_path):
        try:
            with open(result_path) as f:
                status = json.load(f)
            if status.get("status") == "updating":
                raise HTTPException(409, f"Update in progress: {status.get('message', '...')}")
        except (json.JSONDecodeError, HTTPException):
            if isinstance(status, dict) and status.get("status") == "updating":
                raise

    # Write trigger file
    trigger_data = {
        "requested_at": datetime.now(timezone.utc).isoformat(),
        "requested_by": user.get("sub", user.get("email", "unknown")),
    }
    with open(trigger_path, "w") as f:
        json.dump(trigger_data, f)

    # Clear the version check cache so next check picks up new version
    try:
        r = _redis_conn()
        r.delete("update_check_cache")
    except Exception:
        pass

    logger.info("Platform update triggered by %s", trigger_data["requested_by"])
    return {"status": "triggered", "message": "Update will begin shortly. The platform will restart automatically."}


@router.get("/update/status")
def update_status(user=Depends(require_role("admin", "analyst", "viewer"))):
    """Check the current update status (written by the host updater script)."""
    result_path = "/data/update-result.json"
    trigger_path = "/data/update-trigger.json"

    # If trigger exists but no result yet, update hasn't started
    if os.path.exists(trigger_path):
        return {"status": "triggered", "message": "Waiting for host updater to start..."}

    if not os.path.exists(result_path):
        return {"status": "idle", "message": "No update in progress", "version": settings.PLATFORM_VERSION}

    try:
        with open(result_path) as f:
            result = json.load(f)
        result["version"] = settings.PLATFORM_VERSION
        return result
    except Exception as e:
        return {"status": "idle", "message": f"Could not read update status: {e}", "version": settings.PLATFORM_VERSION}


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
