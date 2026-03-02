import json
import logging

from fastapi import APIRouter, Depends, HTTPException
from redis import Redis
from rq import Queue
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_role
from app.core.config import settings
from app.db import models
from app.worker_tasks import run_scan_job

logger = logging.getLogger("vulnscan.scan")

router = APIRouter(prefix="/scan", tags=["scan"])


def _redis() -> Redis:
    return Redis.from_url(settings.REDIS_URL)


# ─── Profiles ─────────────────────────────────────────────────────────────────

@router.post("/profiles", response_model=dict)
def create_profile(
    body: dict,
    user=Depends(require_role("admin", "analyst")),
    db: Session = Depends(get_db),
):
    plugin_json = body.get("plugin_selection_json", "{}")
    options_json = body.get("options_json", "{}")

    # Validate JSON
    try:
        json.loads(plugin_json if isinstance(plugin_json, str) else json.dumps(plugin_json))
    except Exception:
        raise HTTPException(400, "plugin_selection_json is not valid JSON")
    try:
        json.loads(options_json if isinstance(options_json, str) else json.dumps(options_json))
    except Exception:
        raise HTTPException(400, "options_json is not valid JSON")

    # Normalize to strings
    if not isinstance(plugin_json, str):
        plugin_json = json.dumps(plugin_json)
    if not isinstance(options_json, str):
        options_json = json.dumps(options_json)

    row = models.Profile(
        workspace_id=user["ws"],
        name=body.get("name", "default"),
        plugin_selection_json=plugin_json,
        options_json=options_json,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return {
        "id": row.id,
        "name": row.name,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }


@router.get("/profiles")
def list_profiles(
    user=Depends(require_role("admin", "analyst", "viewer")),
    db: Session = Depends(get_db),
):
    rows = (
        db.query(models.Profile)
        .filter(models.Profile.workspace_id == user["ws"])
        .order_by(models.Profile.id.desc())
        .all()
    )
    return [
        {
            "id": r.id,
            "name": r.name,
            "plugin_selection_json": r.plugin_selection_json,
            "options_json": r.options_json,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in rows
    ]


# FIX: Add delete profile endpoint
@router.delete("/profiles/{profile_id}")
def delete_profile(
    profile_id: int,
    user=Depends(require_role("admin", "analyst")),
    db: Session = Depends(get_db),
):
    prof = (
        db.query(models.Profile)
        .filter(
            models.Profile.workspace_id == user["ws"],
            models.Profile.id == profile_id,
        )
        .first()
    )
    if not prof:
        raise HTTPException(404, "profile not found")

    # Nullify foreign key references in scan_jobs before deleting
    job_count = (
        db.query(models.ScanJob)
        .filter(
            models.ScanJob.workspace_id == user["ws"],
            models.ScanJob.profile_id == profile_id,
        )
        .count()
    )
    if job_count > 0:
        db.query(models.ScanJob).filter(
            models.ScanJob.workspace_id == user["ws"],
            models.ScanJob.profile_id == profile_id,
        ).update({models.ScanJob.profile_id: None}, synchronize_session="fetch")

    db.delete(prof)
    try:
        db.commit()
    except Exception as e:
        db.rollback()
        logger.error("Failed to delete profile #%d: %s", profile_id, e)
        raise HTTPException(500, f"Failed to delete profile: {e}")
    logger.info("Deleted profile #%d (unlinked %d jobs)", profile_id, job_count)
    return {"ok": True, "deleted_profile_id": profile_id, "unlinked_jobs": job_count}


# ─── Jobs ──────────────────────────────────────────────────────────────────────

@router.post("/jobs")
def create_job(
    body: dict,
    user=Depends(require_role("admin", "analyst")),
    db: Session = Depends(get_db),
):
    target = (body.get("target") or "").strip()
    if not target:
        raise HTTPException(400, "target is required")

    profile_id = body.get("profile_id")
    if not profile_id:
        raise HTTPException(400, "profile_id is required")

    try:
        profile_id = int(profile_id)
    except (TypeError, ValueError):
        raise HTTPException(400, "profile_id must be an integer")

    scan_type = body.get("scan_type", "internal")
    if scan_type not in ("internal", "external"):
        scan_type = "internal"

    prof = (
        db.query(models.Profile)
        .filter(
            models.Profile.workspace_id == user["ws"],
            models.Profile.id == profile_id,
        )
        .first()
    )
    if not prof:
        raise HTTPException(404, "profile not found")

    job = models.ScanJob(
        workspace_id=user["ws"],
        target=target,
        profile_id=prof.id,
        status="queued",
        scan_type=scan_type,
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    try:
        q = Queue("scans", connection=_redis())
        q.enqueue(run_scan_job, job.id, job_timeout=600)
        logger.info("Enqueued scan job #%d target=%s", job.id, target)
    except Exception as e:
        job.status = "failed"
        job.meta_json = json.dumps({
            "error": f"Failed to enqueue: {e}",
            "error_type": "queue",
            "error_detail": (
                "Could not submit the scan job to the task queue. "
                "The Redis worker may be down or unreachable. "
                "Check that the 'worker' container is running."
            ),
        })
        db.commit()
        raise HTTPException(503, f"Could not enqueue job: {e}")

    return {
        "id": job.id,
        "target": job.target,
        "status": job.status,
        "scan_type": job.scan_type,
        "profile_id": job.profile_id,
        "created_at": job.created_at.isoformat() if job.created_at else None,
    }


@router.get("/jobs")
def list_jobs(
    user=Depends(require_role("admin", "analyst", "viewer")),
    db: Session = Depends(get_db),
):
    rows = (
        db.query(models.ScanJob)
        .filter(models.ScanJob.workspace_id == user["ws"])
        .order_by(models.ScanJob.id.desc())
        .all()
    )
    return [
        {
            "id": r.id,
            "target": r.target,
            "profile_id": r.profile_id,
            "status": r.status,
            "scan_type": r.scan_type or "internal",
            "created_at": r.created_at.isoformat() if r.created_at else None,
            "finished_at": r.finished_at.isoformat() if r.finished_at else None,
            "error_info": _extract_error_info(r.meta_json) if r.status == "failed" else None,
        }
        for r in rows
    ]


def _extract_error_info(meta_json: str | None) -> dict | None:
    """Extract user-friendly error info from job meta_json."""
    if not meta_json:
        return None
    try:
        meta = json.loads(meta_json)
        if "error" in meta:
            return {
                "error": meta.get("error", "Unknown error"),
                "error_type": meta.get("error_type", "unknown"),
                "error_detail": meta.get("error_detail", ""),
            }
    except Exception:
        pass
    return None


@router.get("/jobs/{job_id}")
def job_detail(
    job_id: int,
    user=Depends(require_role("admin", "analyst", "viewer")),
    db: Session = Depends(get_db),
):
    job = (
        db.query(models.ScanJob)
        .filter(
            models.ScanJob.workspace_id == user["ws"],
            models.ScanJob.id == job_id,
        )
        .first()
    )
    if not job:
        raise HTTPException(404, "job not found")

    findings = (
        db.query(models.Finding)
        .filter(
            models.Finding.workspace_id == user["ws"],
            models.Finding.job_id == job_id,
        )
        .order_by(models.Finding.risk_score.desc().nullslast())
        .all()
    )

    # FIX: Include error_info in job detail response so the UI can display it
    error_info = _extract_error_info(job.meta_json) if job.status == "failed" else None

    return {
        "job": {
            "id": job.id,
            "target": job.target,
            "profile_id": job.profile_id,
            "status": job.status,
            "scan_type": job.scan_type or "internal",
            "created_at": job.created_at.isoformat() if job.created_at else None,
            "finished_at": job.finished_at.isoformat() if job.finished_at else None,
            "meta_json": job.meta_json,
            "error_info": error_info,
        },
        "findings": [
            {
                "id": f.id,
                "plugin_id": f.plugin_id,
                "title": f.title,
                "severity": f.severity,
                "description": f.description,
                "remediation": f.remediation,
                "evidence": f.evidence,
                "fingerprint": f.fingerprint,
                "cvss_base": f.cvss_base,
                "risk_score": f.risk_score,
                "confidence": f.confidence,
                "is_kev": f.is_kev,
                "status": f.status,
                "sla_days": f.sla_days,
                "compliance_json": f.compliance_json,
                "created_at": f.created_at.isoformat() if f.created_at else None,
            }
            for f in findings
        ],
    }


@router.delete("/jobs/{job_id}")
def delete_job(
    job_id: int,
    user=Depends(require_role("admin", "analyst")),
    db: Session = Depends(get_db),
):
    job = (
        db.query(models.ScanJob)
        .filter(
            models.ScanJob.workspace_id == user["ws"],
            models.ScanJob.id == job_id,
        )
        .first()
    )
    if not job:
        raise HTTPException(404, "job not found")

    # Delete associated findings first
    db.query(models.Finding).filter(
        models.Finding.job_id == job_id,
        models.Finding.workspace_id == user["ws"],
    ).delete()

    db.delete(job)
    db.commit()
    logger.info("Deleted scan job #%d", job_id)
    return {"ok": True, "deleted_job_id": job_id}


@router.post("/suppress")
def suppress(
    body: dict,
    user=Depends(require_role("admin", "analyst")),
    db: Session = Depends(get_db),
):
    fp = body.get("fingerprint", "")
    reason = body.get("reason", "")
    if not fp:
        raise HTTPException(400, "missing fingerprint")

    existing = (
        db.query(models.SuppressedFinding)
        .filter(
            models.SuppressedFinding.workspace_id == user["ws"],
            models.SuppressedFinding.fingerprint == fp,
        )
        .first()
    )
    if existing:
        existing.reason = reason
    else:
        row = models.SuppressedFinding(
            workspace_id=user["ws"], fingerprint=fp, reason=reason
        )
        db.add(row)
    db.commit()
    return {"ok": True}
