import json
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from rq import Queue
from redis import Redis

from app.api.deps import get_db, require_role
from app.db import models
from app.core.config import settings
from app.worker_tasks import run_scan_job  # enqueued function

router = APIRouter(prefix="/scan", tags=["scan"])

def _redis():
    return Redis.from_url(settings.REDIS_URL)

@router.post("/profiles", response_model=dict)
def create_profile(body: dict, user=Depends(require_role("admin","analyst")), db: Session = Depends(get_db)):
    row = models.Profile(
        workspace_id=user["workspace_id"],
        name=body.get("name","default"),
        plugin_selection_json=body.get("plugin_selection_json","{}"),
        options_json=body.get("options_json","{}"),
    )
    db.add(row); db.commit(); db.refresh(row)
    return {"id": row.id}

@router.get("/profiles")
def list_profiles(user=Depends(require_role("admin","analyst","viewer")), db: Session = Depends(get_db)):
    rows = db.query(models.Profile).filter(models.Profile.workspace_id==user["workspace_id"]).order_by(models.Profile.id.desc()).all()
    return rows

@router.post("/jobs")
def create_job(body: dict, user=Depends(require_role("admin","analyst")), db: Session = Depends(get_db)):
    target = (body.get("target") or "").strip()
    profile_id = int(body.get("profile_id", 0))
    prof = db.query(models.Profile).filter(models.Profile.workspace_id==user["workspace_id"], models.Profile.id==profile_id).first()
    if not prof:
        raise HTTPException(404, "profile not found")

    job = models.ScanJob(workspace_id=user["workspace_id"], target=target, profile_id=prof.id, status="queued")
    db.add(job); db.commit(); db.refresh(job)

    q = Queue("scans", connection=_redis())
    q.enqueue(run_scan_job, job.id)

    return {"id": job.id, "status": job.status}

@router.get("/jobs")
def list_jobs(user=Depends(require_role("admin","analyst","viewer")), db: Session = Depends(get_db)):
    rows = db.query(models.ScanJob).filter(models.ScanJob.workspace_id==user["workspace_id"]).order_by(models.ScanJob.id.desc()).all()
    return rows

@router.get("/jobs/{job_id}")
def job_detail(job_id: int, user=Depends(require_role("admin","analyst","viewer")), db: Session = Depends(get_db)):
    job = db.query(models.ScanJob).filter(models.ScanJob.workspace_id==user["workspace_id"], models.ScanJob.id==job_id).first()
    if not job:
        raise HTTPException(404, "job not found")
    findings = db.query(models.Finding).filter(models.Finding.workspace_id==user["workspace_id"], models.Finding.job_id==job_id).order_by(models.Finding.risk_score.desc().nullslast()).all()
    return {"job": job, "findings": findings}

@router.post("/suppress")
def suppress(body: dict, user=Depends(require_role("admin","analyst")), db: Session = Depends(get_db)):
    fp = body.get("fingerprint","")
    reason = body.get("reason","")
    if not fp:
        raise HTTPException(400, "missing fingerprint")
    row = models.SuppressedFinding(workspace_id=user["workspace_id"], fingerprint=fp, reason=reason)
    db.add(row); db.commit()
    return {"ok": True}