"""
AI Analysis API — endpoints for multi-provider AI deep analysis of scan findings.
"""
import json
import logging
from datetime import datetime, timezone

import redis
from rq import Queue
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db import models
from app.core.config import settings
from app.api.deps import get_db, require_role

logger = logging.getLogger("vulnscan.api.ai")

router = APIRouter(prefix="/ai", tags=["ai"])

VALID_MODES = {"validate", "full", "full_exploit"}


def _redis():
    return redis.from_url(settings.REDIS_URL, decode_responses=True)


# ─────────────────────────────────────────────────────────────────────────
# GET /ai/providers — list configured AI providers
# ─────────────────────────────────────────────────────────────────────────

@router.get("/providers")
def list_providers(user=Depends(require_role("admin", "analyst", "viewer"))):
    """Return list of available AI providers (based on .env config)."""
    return {"providers": settings.available_ai_providers()}


# ─────────────────────────────────────────────────────────────────────────
# POST /ai/analyze — start AI analysis
# ─────────────────────────────────────────────────────────────────────────

@router.post("/analyze")
def start_analysis(
    body: dict,
    user=Depends(require_role("admin", "analyst")),
    db: Session = Depends(get_db),
):
    """Start an AI deep analysis on a completed scan job."""
    job_id = body.get("job_id")
    provider = body.get("provider", "")
    mode = body.get("mode", "validate")

    if not job_id:
        raise HTTPException(400, "job_id is required")
    if mode not in VALID_MODES:
        raise HTTPException(400, f"Invalid mode: {mode}. Valid: {', '.join(VALID_MODES)}")

    # Validate provider is available
    available = [p["id"] for p in settings.available_ai_providers()]
    if not available:
        raise HTTPException(400, "No AI providers configured. Set API keys in .env")
    if provider not in available:
        raise HTTPException(400, f"Provider '{provider}' not configured. Available: {', '.join(available)}")

    # Validate job exists and belongs to workspace
    job = db.query(models.ScanJob).filter(
        models.ScanJob.id == job_id,
        models.ScanJob.workspace_id == user["ws"],
    ).first()
    if not job:
        raise HTTPException(404, "Job not found")
    if job.status != "done":
        raise HTTPException(400, f"Job must be completed first (current status: {job.status})")

    # Check for findings
    finding_count = db.query(models.Finding).filter(
        models.Finding.job_id == job_id,
    ).count()
    if finding_count == 0:
        raise HTTPException(400, "No findings to analyze")

    # Dedup: check if same analysis is already running
    r = _redis()
    lock_key = f"ai_analysis:{job_id}:{provider}:{mode}"
    if not r.set(lock_key, "1", nx=True, ex=900):
        # Check if there's an existing analysis still running
        existing = db.query(models.AiAnalysis).filter(
            models.AiAnalysis.job_id == job_id,
            models.AiAnalysis.provider == provider,
            models.AiAnalysis.mode == mode,
            models.AiAnalysis.status.in_(["queued", "running"]),
        ).first()
        if existing:
            return {"analysis_id": existing.id, "status": existing.status, "message": "Analysis already in progress"}
        # Lock exists but no running analysis — clear stale lock
        r.delete(lock_key)
        r.set(lock_key, "1", nx=True, ex=900)

    # Create analysis record
    analysis = models.AiAnalysis(
        workspace_id=user["ws"],
        job_id=job_id,
        provider=provider,
        mode=mode,
        status="queued",
        progress_json=json.dumps({"pct": 0, "step": "Queued..."}),
    )
    db.add(analysis)
    db.commit()
    db.refresh(analysis)

    # Enqueue RQ task on "ai" queue
    try:
        redis_conn = redis.from_url(settings.REDIS_URL)
        q = Queue("ai", connection=redis_conn)
        from app.worker_tasks import run_ai_analysis
        q.enqueue(run_ai_analysis, analysis.id, job_timeout=settings.AI_ANALYSIS_TIMEOUT)
        logger.info("AI analysis #%d queued: job=%d provider=%s mode=%s", analysis.id, job_id, provider, mode)
    except Exception as e:
        analysis.status = "failed"
        analysis.error = f"Failed to enqueue: {e}"
        db.commit()
        r.delete(lock_key)
        raise HTTPException(500, f"Failed to enqueue analysis: {e}")

    return {
        "analysis_id": analysis.id,
        "status": "queued",
        "provider": provider,
        "mode": mode,
        "findings_count": finding_count,
    }


# ─────────────────────────────────────────────────────────────────────────
# GET /ai/status/{analysis_id} — poll analysis progress
# ─────────────────────────────────────────────────────────────────────────

@router.get("/status/{analysis_id}")
def analysis_status(
    analysis_id: int,
    user=Depends(require_role("admin", "analyst", "viewer")),
    db: Session = Depends(get_db),
):
    """Poll the status/progress of an AI analysis."""
    analysis = db.query(models.AiAnalysis).filter(
        models.AiAnalysis.id == analysis_id,
        models.AiAnalysis.workspace_id == user["ws"],
    ).first()
    if not analysis:
        raise HTTPException(404, "Analysis not found")

    progress = {}
    if analysis.progress_json:
        try:
            progress = json.loads(analysis.progress_json)
        except Exception:
            pass

    result = {
        "id": analysis.id,
        "status": analysis.status,
        "provider": analysis.provider,
        "mode": analysis.mode,
        "progress": progress,
        "token_usage": analysis.token_usage,
        "duration_seconds": analysis.duration_seconds,
        "error": analysis.error,
        "created_at": analysis.created_at.isoformat() if analysis.created_at else None,
        "finished_at": analysis.finished_at.isoformat() if analysis.finished_at else None,
    }

    # Include results if done
    if analysis.status == "done" and analysis.result_json:
        try:
            result["result"] = json.loads(analysis.result_json)
        except Exception:
            result["result"] = None

    return result


# ─────────────────────────────────────────────────────────────────────────
# GET /ai/results/{job_id} — get all analyses for a job
# ─────────────────────────────────────────────────────────────────────────

@router.get("/results/{job_id}")
def job_analyses(
    job_id: int,
    user=Depends(require_role("admin", "analyst", "viewer")),
    db: Session = Depends(get_db),
):
    """Get all AI analyses for a scan job (history)."""
    analyses = db.query(models.AiAnalysis).filter(
        models.AiAnalysis.job_id == job_id,
        models.AiAnalysis.workspace_id == user["ws"],
    ).order_by(models.AiAnalysis.created_at.desc()).all()

    results = []
    for a in analyses:
        item = {
            "id": a.id,
            "provider": a.provider,
            "mode": a.mode,
            "status": a.status,
            "token_usage": a.token_usage,
            "duration_seconds": a.duration_seconds,
            "error": a.error,
            "created_at": a.created_at.isoformat() if a.created_at else None,
            "finished_at": a.finished_at.isoformat() if a.finished_at else None,
        }
        if a.status == "done" and a.result_json:
            try:
                item["result"] = json.loads(a.result_json)
            except Exception:
                item["result"] = None
        results.append(item)

    return {"analyses": results}


# ─────────────────────────────────────────────────────────────────────────
# POST /ai/poc — generate PoC for a single finding
# ─────────────────────────────────────────────────────────────────────────

@router.post("/poc")
def generate_poc_endpoint(
    body: dict,
    user=Depends(require_role("admin", "analyst")),
    db: Session = Depends(get_db),
):
    """Generate a PoC exploit script for a specific finding.

    Accepts either:
      - { finding_id } — standalone mode, auto-creates/reuses an analysis record
      - { analysis_id, finding_id } — legacy mode tied to an existing analysis
    """
    analysis_id = body.get("analysis_id")
    finding_id = body.get("finding_id")

    if not finding_id:
        raise HTTPException(400, "finding_id is required")

    # Look up finding directly (no job_id filter so it works across jobs)
    finding = db.query(models.Finding).filter(
        models.Finding.id == finding_id,
    ).first()
    if not finding:
        raise HTTPException(404, "Finding not found")

    # Verify the finding's job belongs to this workspace
    job = db.query(models.ScanJob).filter(
        models.ScanJob.id == finding.job_id,
        models.ScanJob.workspace_id == user["ws"],
    ).first()
    if not job:
        raise HTTPException(404, "Finding not found")

    # Resolve or auto-create an analysis record for this job
    if analysis_id:
        analysis = db.query(models.AiAnalysis).filter(
            models.AiAnalysis.id == analysis_id,
            models.AiAnalysis.workspace_id == user["ws"],
        ).first()
        if not analysis:
            raise HTTPException(404, "Analysis not found")
    else:
        # Reuse any existing "done" analysis for this job, or create a poc-only one
        analysis = db.query(models.AiAnalysis).filter(
            models.AiAnalysis.job_id == finding.job_id,
            models.AiAnalysis.workspace_id == user["ws"],
            models.AiAnalysis.status == "done",
        ).order_by(models.AiAnalysis.created_at.desc()).first()

        if not analysis:
            # Pick first available provider
            available = settings.available_ai_providers()
            if not available:
                raise HTTPException(400, "No AI providers configured. Set API keys in .env")
            provider_id = available[0]["id"]

            analysis = models.AiAnalysis(
                workspace_id=user["ws"],
                job_id=finding.job_id,
                provider=provider_id,
                mode="poc_only",
                status="done",
                result_json=json.dumps({}),
                progress_json=json.dumps({"pct": 100, "step": "PoC generation"}),
            )
            db.add(analysis)
            db.commit()
            db.refresh(analysis)

    # Check if PoC already exists
    if analysis.result_json:
        try:
            existing = json.loads(analysis.result_json)
            if str(finding_id) in existing.get("poc_results", {}):
                return {
                    "status": "done",
                    "analysis_id": analysis.id,
                    "poc": existing["poc_results"][str(finding_id)],
                }
        except Exception:
            pass

    # Enqueue PoC generation
    try:
        redis_conn = redis.from_url(settings.REDIS_URL)
        q = Queue("ai", connection=redis_conn)
        from app.worker_tasks import run_ai_poc
        q.enqueue(run_ai_poc, analysis.id, finding_id, job_timeout=120)
        logger.info("PoC generation queued: analysis=%d finding=%d", analysis.id, finding_id)
    except Exception as e:
        raise HTTPException(500, f"Failed to enqueue PoC generation: {e}")

    return {"status": "queued", "analysis_id": analysis.id, "finding_id": finding_id}

