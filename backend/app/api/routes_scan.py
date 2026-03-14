import json
import logging
from datetime import datetime, timezone, timedelta

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

    try:
        json.loads(plugin_json if isinstance(plugin_json, str) else json.dumps(plugin_json))
    except Exception:
        raise HTTPException(400, "plugin_selection_json is not valid JSON")
    try:
        json.loads(options_json if isinstance(options_json, str) else json.dumps(options_json))
    except Exception:
        raise HTTPException(400, "options_json is not valid JSON")

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


@router.put("/profiles/{profile_id}", response_model=dict)
def update_profile(
    profile_id: int,
    body: dict,
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

    if "name" in body:
        prof.name = body["name"]

    if "plugin_selection_json" in body:
        pj = body["plugin_selection_json"]
        try:
            json.loads(pj if isinstance(pj, str) else json.dumps(pj))
        except Exception:
            raise HTTPException(400, "plugin_selection_json is not valid JSON")
        prof.plugin_selection_json = pj if isinstance(pj, str) else json.dumps(pj)

    if "options_json" in body:
        oj = body["options_json"]
        try:
            json.loads(oj if isinstance(oj, str) else json.dumps(oj))
        except Exception:
            raise HTTPException(400, "options_json is not valid JSON")
        prof.options_json = oj if isinstance(oj, str) else json.dumps(oj)

    try:
        db.commit()
        db.refresh(prof)
    except Exception as e:
        db.rollback()
        logger.error("Failed to update profile #%d: %s", profile_id, e)
        raise HTTPException(500, f"Failed to update profile: {e}")

    logger.info("Updated profile #%d (%s)", profile_id, prof.name)
    return {
        "id": prof.id,
        "name": prof.name,
        "plugin_selection_json": prof.plugin_selection_json,
        "options_json": prof.options_json,
        "created_at": prof.created_at.isoformat() if prof.created_at else None,
    }


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
        # RQ timeout = scan budget + 300s headroom for post-processing & DB writes
        rq_timeout = settings.SCAN_BUDGET_SECONDS + 300
        q.enqueue(run_scan_job, job.id, job_timeout=rq_timeout)
        logger.info("Enqueued scan job #%d target=%s type=%s timeout=%ds", job.id, target, scan_type, rq_timeout)
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
            "meta_json": r.meta_json if r.status == "running" else None,
            "error_info": _extract_error_info(r.meta_json) if r.status == "failed" else None,
        }
        for r in rows
    ]


def _extract_error_info(meta_json: str | None) -> dict | None:
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
                "references_json": f.references_json,
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

    target = job.target
    ws_id = user["ws"]

    db.query(models.Finding).filter(
        models.Finding.job_id == job_id,
        models.Finding.workspace_id == ws_id,
    ).delete()

    db.delete(job)
    db.commit()
    logger.info("Deleted scan job #%d", job_id)

    # Rebuild Neo4j graph from remaining findings
    try:
        from app.graph.neo4j_client import Neo4jClient
        neo = Neo4jClient()
        remaining = (
            db.query(models.Finding)
            .filter(models.Finding.workspace_id == ws_id)
            .all()
        )
        neo.sync_from_findings(ws_id, [
            {
                "target": f.target,
                "cve": f.evidence.split("CVE-")[1].split(" ")[0].split(")")[0] if "CVE-" in (f.evidence or "") else "",
                "plugin_id": f.plugin_id,
                "risk_score": f.risk_score,
            }
            for f in remaining
        ])
        neo.close()
    except Exception as e:
        logger.debug("Neo4j graph sync after delete: %s", e)

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

# ─── Rescan ────────────────────────────────────────────────────────────────────

@router.post("/jobs/{job_id}/rescan")
def rescan_job(
    job_id: int,
    user=Depends(require_role("admin", "analyst")),
    db: Session = Depends(get_db),
):
    """Create a new scan job with the same target/profile/type as an existing job."""
    original = (
        db.query(models.ScanJob)
        .filter(
            models.ScanJob.workspace_id == user["ws"],
            models.ScanJob.id == job_id,
        )
        .first()
    )
    if not original:
        raise HTTPException(404, "job not found")

    new_job = models.ScanJob(
        workspace_id=user["ws"],
        target=original.target,
        profile_id=original.profile_id,
        status="queued",
        scan_type=original.scan_type or "internal",
    )
    db.add(new_job)
    db.commit()
    db.refresh(new_job)

    try:
        q = Queue("scans", connection=_redis())
        rq_timeout = settings.SCAN_BUDGET_SECONDS + 300
        q.enqueue(run_scan_job, new_job.id, job_timeout=rq_timeout)
        logger.info("Rescan enqueued: job #%d (from #%d) target=%s", new_job.id, job_id, original.target)
    except Exception as e:
        new_job.status = "failed"
        new_job.meta_json = json.dumps({"error": f"Failed to enqueue rescan: {e}"})
        db.commit()
        raise HTTPException(503, f"Could not enqueue rescan: {e}")

    return {
        "id": new_job.id,
        "original_job_id": job_id,
        "target": new_job.target,
        "status": new_job.status,
    }


# ─── Scan History (per host) ──────────────────────────────────────────────────

@router.get("/history/{target:path}")
def scan_history(
    target: str,
    user=Depends(require_role("admin", "analyst", "viewer")),
    db: Session = Depends(get_db),
):
    """Get all scan jobs and finding summaries for a specific target."""
    ws = user["ws"]
    jobs = (
        db.query(models.ScanJob)
        .filter(
            models.ScanJob.workspace_id == ws,
            models.ScanJob.target == target,
        )
        .order_by(models.ScanJob.created_at.desc())
        .all()
    )

    history = []
    for j in jobs:
        finding_counts = {}
        findings = (
            db.query(models.Finding.severity, models.Finding.id)
            .filter(models.Finding.job_id == j.id, models.Finding.workspace_id == ws)
            .all()
        )
        for f_sev, _ in findings:
            finding_counts[f_sev] = finding_counts.get(f_sev, 0) + 1

        history.append({
            "job_id": j.id,
            "target": j.target,
            "scan_type": j.scan_type or "internal",
            "profile_id": j.profile_id,
            "status": j.status,
            "created_at": j.created_at.isoformat() if j.created_at else None,
            "finished_at": j.finished_at.isoformat() if j.finished_at else None,
            "severity_counts": finding_counts,
            "total_findings": sum(finding_counts.values()),
        })

    return {"target": target, "scans": history, "total_scans": len(history)}


# ─── Scan Schedules ───────────────────────────────────────────────────────────

@router.get("/schedules")
def list_schedules(
    user=Depends(require_role("admin", "analyst", "viewer")),
    db: Session = Depends(get_db),
):
    rows = (
        db.query(models.ScanSchedule)
        .filter(models.ScanSchedule.workspace_id == user["ws"])
        .order_by(models.ScanSchedule.id.desc())
        .all()
    )
    return [
        {
            "id": r.id,
            "name": r.name,
            "target": r.target,
            "profile_id": r.profile_id,
            "scan_type": r.scan_type,
            "schedule_type": r.schedule_type or "interval",
            "interval_hours": r.interval_hours,
            "custom_datetime": r.custom_datetime.isoformat() if r.custom_datetime else None,
            "repeat": r.repeat if r.repeat is not None else True,
            "enabled": r.enabled,
            "last_run_at": r.last_run_at.isoformat() if r.last_run_at else None,
            "next_run_at": r.next_run_at.isoformat() if r.next_run_at else None,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in rows
    ]


@router.post("/schedules")
def create_schedule(
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

    schedule_type = body.get("schedule_type", "interval")  # "interval" or "custom"
    interval = int(body.get("interval_hours", 24))
    if interval < 1:
        interval = 1

    now_utc = datetime.now(timezone.utc)
    custom_dt = None
    repeat = body.get("repeat", True)

    if schedule_type == "custom":
        # Parse custom datetime from ISO string
        raw_dt = body.get("custom_datetime", "")
        if not raw_dt:
            raise HTTPException(400, "custom_datetime is required for custom schedule type")
        try:
            custom_dt = datetime.fromisoformat(raw_dt.replace("Z", "+00:00"))
            if custom_dt.tzinfo is None:
                custom_dt = custom_dt.replace(tzinfo=timezone.utc)
        except Exception:
            raise HTTPException(400, f"Invalid datetime format: {raw_dt}. Use ISO 8601 (e.g. 2026-03-10T14:30:00)")
        next_run = custom_dt
    else:
        next_run = now_utc + timedelta(hours=interval)

    sched = models.ScanSchedule(
        workspace_id=user["ws"],
        name=body.get("name", f"Schedule: {target}"),
        target=target,
        profile_id=int(profile_id),
        scan_type=body.get("scan_type", "internal"),
        schedule_type=schedule_type,
        interval_hours=interval,
        custom_datetime=custom_dt,
        repeat=repeat,
        enabled=body.get("enabled", True),
        next_run_at=next_run,
    )
    db.add(sched)
    db.commit()
    db.refresh(sched)
    mode = f"custom ({custom_dt.isoformat()})" if schedule_type == "custom" else f"every {interval}h"
    logger.info("Schedule #%d created: %s %s", sched.id, target, mode)
    return {"id": sched.id, "name": sched.name, "next_run_at": sched.next_run_at.isoformat() if sched.next_run_at else None}


@router.put("/schedules/{sched_id}/toggle")
def toggle_schedule(
    sched_id: int,
    user=Depends(require_role("admin", "analyst")),
    db: Session = Depends(get_db),
):
    sched = (
        db.query(models.ScanSchedule)
        .filter(models.ScanSchedule.workspace_id == user["ws"], models.ScanSchedule.id == sched_id)
        .first()
    )
    if not sched:
        raise HTTPException(404, "schedule not found")
    sched.enabled = not sched.enabled
    db.commit()
    return {"id": sched.id, "enabled": sched.enabled}


@router.delete("/schedules/{sched_id}")
def delete_schedule(
    sched_id: int,
    user=Depends(require_role("admin", "analyst")),
    db: Session = Depends(get_db),
):
    sched = (
        db.query(models.ScanSchedule)
        .filter(models.ScanSchedule.workspace_id == user["ws"], models.ScanSchedule.id == sched_id)
        .first()
    )
    if not sched:
        raise HTTPException(404, "schedule not found")
    db.delete(sched)
    db.commit()
    return {"ok": True}