"""
Settings API — manage platform configuration from the UI.
"""
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
from app.core.password import hash_password, verify_password
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
            "updated_at": u.updated_at.isoformat() if u.updated_at else None,
            "last_login_at": u.last_login_at.isoformat() if u.last_login_at else None,
            "last_login_ip": u.last_login_ip,
            "last_login_location": u.last_login_location,
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

    pw_hash = hash_password(body.password)
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


class PasswordChange(BaseModel):
    current_password: str
    new_password: str


@router.put("/users/me/password")
def change_own_password(
    body: PasswordChange,
    user=Depends(require_role("admin", "analyst", "viewer")),
    db: Session = Depends(get_db),
):
    """Allow any authenticated user to change their own password."""
    target = db.query(models.User).filter(
        models.User.workspace_id == user["ws"],
        models.User.email == user["sub"],
    ).first()
    if not target:
        raise HTTPException(404, "User not found")
    if not verify_password(body.current_password, target.password_hash):
        raise HTTPException(403, "Current password is incorrect")
    if len(body.new_password) < 6:
        raise HTTPException(400, "New password must be at least 6 characters")
    target.password_hash = hash_password(body.new_password)
    target.updated_at = datetime.now(timezone.utc)
    db.commit()
    logger.info("Password changed by %s", user.get("sub", "?"))
    return {"ok": True, "message": "Password updated successfully"}


class AdminPasswordReset(BaseModel):
    new_password: str


@router.put("/users/{user_id}/password")
def admin_reset_password(
    user_id: int,
    body: AdminPasswordReset,
    user=Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """Allow admins to reset any user's password."""
    target = db.query(models.User).filter(
        models.User.id == user_id,
        models.User.workspace_id == user["ws"],
    ).first()
    if not target:
        raise HTTPException(404, "User not found")
    if len(body.new_password) < 6:
        raise HTTPException(400, "New password must be at least 6 characters")
    target.password_hash = hash_password(body.new_password)
    target.updated_at = datetime.now(timezone.utc)
    db.commit()
    logger.info("Password reset for %s (#%d) by admin %s", target.email, user_id, user.get("sub", "?"))
    return {"ok": True, "message": f"Password reset for {target.email}"}


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

    # Return cached result if available — but invalidate if the running
    # version has changed (e.g. after an update + restart).
    cached = r.get(cache_key)
    if cached:
        try:
            cached_data = json.loads(cached)
            if cached_data.get("current") == settings.PLATFORM_VERSION:
                return cached_data
            # Version changed since cache was written — re-check
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
        status = None
        try:
            with open(result_path) as f:
                status = json.load(f)
        except (OSError, json.JSONDecodeError) as exc:
            # Corrupt or unreadable result file — treat it as "no update in
            # progress" instead of blocking the trigger.
            logger.warning("Ignoring unreadable %s: %s", result_path, exc)
        if isinstance(status, dict) and status.get("status") == "updating":
            raise HTTPException(409, f"Update in progress: {status.get('message', '...')}")

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


# ─── SLA Policies ─────────────────────────────────────────────────────────────

DEFAULT_SLA = {
    "policies": [
        {"sev": "critical", "days": 2,  "hours": 4,  "escalate": True,  "notify": ["@security-leads"]},
        {"sev": "high",     "days": 7,  "hours": 24, "escalate": True,  "notify": ["@asset-owner"]},
        {"sev": "medium",   "days": 30, "hours": 72, "escalate": False, "notify": ["@asset-owner"]},
        {"sev": "low",      "days": 90, "hours": 0,  "escalate": False, "notify": []},
        {"sev": "info",     "days": 365,"hours": 0,  "escalate": False, "notify": []},
    ],
    "breach_action": "notify",                # notify | ticket | page | block
    "business_hours_only": False,
    "pause_states": ["accepted-risk", "false-positive", "awaiting-vendor", "in-progress"],
    "compliance_preset": "custom",            # custom | pci | hipaa | soc2 | iso | cisa
}


def _get_setting(db: Session, ws: int, key: str, default: dict) -> dict:
    row = db.query(models.WorkspaceSetting).filter(
        models.WorkspaceSetting.workspace_id == ws,
        models.WorkspaceSetting.key == key,
    ).first()
    if not row:
        return default
    try:
        return json.loads(row.value_json)
    except Exception:
        return default


def _set_setting(db: Session, ws: int, key: str, value: dict) -> None:
    row = db.query(models.WorkspaceSetting).filter(
        models.WorkspaceSetting.workspace_id == ws,
        models.WorkspaceSetting.key == key,
    ).first()
    if row:
        row.value_json = json.dumps(value)
        row.updated_at = datetime.now(timezone.utc)
    else:
        row = models.WorkspaceSetting(
            workspace_id=ws,
            key=key,
            value_json=json.dumps(value),
        )
        db.add(row)
    db.commit()


@router.get("/sla")
def get_sla(user=Depends(require_role("admin", "analyst", "viewer")), db: Session = Depends(get_db)):
    return _get_setting(db, user["ws"], "sla", DEFAULT_SLA)


class SLAUpdate(BaseModel):
    policies: list | None = None
    breach_action: str | None = None
    business_hours_only: bool | None = None
    pause_states: list | None = None
    compliance_preset: str | None = None


@router.put("/sla")
def put_sla(body: SLAUpdate, user=Depends(require_role("admin", "analyst")), db: Session = Depends(get_db)):
    current = _get_setting(db, user["ws"], "sla", DEFAULT_SLA)
    incoming = body.dict(exclude_unset=True)
    current.update(incoming)
    _set_setting(db, user["ws"], "sla", current)
    return current


@router.post("/sla/reset")
def reset_sla(user=Depends(require_role("admin", "analyst")), db: Session = Depends(get_db)):
    _set_setting(db, user["ws"], "sla", DEFAULT_SLA)
    return DEFAULT_SLA


# ── Notification Preferences ───────────────────────────────────────────────

_VALID_NOTIF_EVENTS = {
    "critical_finding", "cisa_kev_match", "scan_completed",
    "scan_failed", "new_asset_discovered", "weekly_digest",
}
_VALID_NOTIF_CHANNELS = {"email", "slack", "webhook"}

DEFAULT_NOTIFICATION_PREFS = {
    "critical_finding":     {"email": True,  "slack": True,  "webhook": True},
    "cisa_kev_match":       {"email": True,  "slack": True,  "webhook": False},
    "scan_completed":       {"email": False, "slack": True,  "webhook": False},
    "scan_failed":          {"email": True,  "slack": True,  "webhook": True},
    "new_asset_discovered": {"email": False, "slack": False, "webhook": True},
    "weekly_digest":        {"email": True,  "slack": False, "webhook": False},
}


@router.get("/notifications")
def get_notification_prefs(
    user=Depends(require_role("admin", "analyst", "viewer")),
    db: Session = Depends(get_db),
):
    return _get_setting(db, user["ws"], "notification_preferences", DEFAULT_NOTIFICATION_PREFS)


@router.put("/notifications")
def put_notification_prefs(
    body: dict,
    user=Depends(require_role("admin", "analyst")),
    db: Session = Depends(get_db),
):
    # Validate: only known event keys with known channel bools
    cleaned = {}
    for event_key, channels in body.items():
        if event_key not in _VALID_NOTIF_EVENTS:
            raise HTTPException(400, f"Unknown event type: {event_key}")
        if not isinstance(channels, dict):
            raise HTTPException(400, f"Channels for '{event_key}' must be a dict")
        cleaned[event_key] = {
            ch: bool(channels.get(ch, False))
            for ch in _VALID_NOTIF_CHANNELS
        }

    # Merge with defaults so missing keys get defaults
    current = _get_setting(db, user["ws"], "notification_preferences", DEFAULT_NOTIFICATION_PREFS)
    current.update(cleaned)
    _set_setting(db, user["ws"], "notification_preferences", current)
    return current


@router.post("/notifications/reset")
def reset_notification_prefs(
    user=Depends(require_role("admin", "analyst")),
    db: Session = Depends(get_db),
):
    _set_setting(db, user["ws"], "notification_preferences", DEFAULT_NOTIFICATION_PREFS)
    return DEFAULT_NOTIFICATION_PREFS


# ── Auto AI Analysis ─────────────────────────────────────────────────────

DEFAULT_AUTO_AI = {
    "enabled": False,
    "provider": "",       # empty = auto-detect (prefer claude_cli)
    "mode": "validate",   # validate | full | full_exploit
}


@router.get("/auto-ai")
def get_auto_ai(
    user=Depends(require_role("admin", "analyst", "viewer")),
    db: Session = Depends(get_db),
):
    """Return auto AI analysis configuration."""
    config = _get_setting(db, user["ws"], "auto_ai_analysis", DEFAULT_AUTO_AI)
    # Also return available providers for the UI
    from app.core.config import settings as app_settings
    config["available_providers"] = app_settings.available_ai_providers()
    return config


class AutoAIUpdate(BaseModel):
    enabled: bool | None = None
    provider: str | None = None
    mode: str | None = None


@router.put("/auto-ai")
def put_auto_ai(
    body: AutoAIUpdate,
    user=Depends(require_role("admin", "analyst")),
    db: Session = Depends(get_db),
):
    """Update auto AI analysis configuration."""
    current = _get_setting(db, user["ws"], "auto_ai_analysis", DEFAULT_AUTO_AI)
    incoming = body.dict(exclude_unset=True)

    _valid_modes = ("validate", "full", "full_exploit", "validate_then_exploit")
    if "mode" in incoming and incoming["mode"] not in _valid_modes:
        raise HTTPException(400, f"Mode must be one of: {', '.join(_valid_modes)}")

    current.update(incoming)
    _set_setting(db, user["ws"], "auto_ai_analysis", current)
    logger.info("Auto AI analysis updated by %s: %s", user.get("sub", "?"), current)
    return current


# ── SLA Breach Alert ──────────────────────────────────────────────────────

DEFAULT_SLA_ALERT = {
    "enabled": False,
    "interval_minutes": 60,
}


@router.get("/sla-alert")
def get_sla_alert(
    user=Depends(require_role("admin", "analyst", "viewer")),
    db: Session = Depends(get_db),
):
    return _get_setting(db, user["ws"], "sla_breach_alert", DEFAULT_SLA_ALERT)


class SLAAlertUpdate(BaseModel):
    enabled: bool | None = None
    interval_minutes: int | None = None


@router.put("/sla-alert")
def put_sla_alert(
    body: SLAAlertUpdate,
    user=Depends(require_role("admin", "analyst")),
    db: Session = Depends(get_db),
):
    current = _get_setting(db, user["ws"], "sla_breach_alert", DEFAULT_SLA_ALERT)
    incoming = body.dict(exclude_unset=True)
    if "interval_minutes" in incoming and incoming["interval_minutes"] < 15:
        raise HTTPException(400, "Interval must be at least 15 minutes")
    current.update(incoming)
    _set_setting(db, user["ws"], "sla_breach_alert", current)
    logger.info("SLA breach alert updated by %s: %s", user.get("sub", "?"), current)
    return current


# ── Auto Report Generation ─────────────────────────────────────────────────

DEFAULT_AUTO_REPORT = {
    "enabled": False,
    "format": "pdf",
}


@router.get("/auto-report")
def get_auto_report(
    user=Depends(require_role("admin", "analyst", "viewer")),
    db: Session = Depends(get_db),
):
    """Return auto report generation configuration."""
    return _get_setting(db, user["ws"], "auto_report", DEFAULT_AUTO_REPORT)


class AutoReportUpdate(BaseModel):
    enabled: bool | None = None
    format: str | None = None


@router.put("/auto-report")
def put_auto_report(
    body: AutoReportUpdate,
    user=Depends(require_role("admin", "analyst")),
    db: Session = Depends(get_db),
):
    """Update auto report generation configuration."""
    current = _get_setting(db, user["ws"], "auto_report", DEFAULT_AUTO_REPORT)
    incoming = body.dict(exclude_unset=True)

    if "format" in incoming and incoming["format"] not in ("pdf",):
        raise HTTPException(400, "Format must be: pdf")

    current.update(incoming)
    _set_setting(db, user["ws"], "auto_report", current)
    logger.info("Auto report config updated by %s: %s", user.get("sub", "?"), current)
    return current
