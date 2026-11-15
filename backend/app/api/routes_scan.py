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
from app.risk.cvss_engine import cvss_baseline_from_severity
from app.worker_tasks import run_scan_job

logger = logging.getLogger("vulnscan.scan")

router = APIRouter(prefix="/scan", tags=["scan"])


def _baseline_cvss(severity: str | None) -> float | None:
    """Wrapper so route serializers can use a one-liner."""
    return cvss_baseline_from_severity(severity)


def _redis() -> Redis:
    return Redis.from_url(settings.REDIS_URL)


def _resolve_user_id(db: Session, claims: dict) -> int | None:
    """Fallback for old JWT tokens missing the 'uid' claim."""
    email = claims.get("sub")
    if not email:
        return None
    u = db.query(models.User.id).filter(models.User.email == email).first()
    return u.id if u else None


# ─── Available Plugins ────────────────────────────────────────────────────────

@router.get("/plugins")
def list_plugins(user=Depends(require_role("admin", "analyst", "viewer"))):
    """Return all available scanner plugins with their metadata."""
    from app.scanner.plugins.loader import load_plugins
    plugins = load_plugins()
    result = []
    for pid, plugin in plugins.items():
        meta = getattr(plugin, "meta", None) or getattr(plugin, "META", None)
        if not meta:
            continue
        result.append({
            "plugin_id": meta.plugin_id,
            "name": meta.name,
            "category": meta.category,
            "enabled_by_default": meta.enabled_by_default,
            "timeout_seconds": meta.timeout_seconds,
            "depends_on": list(meta.depends_on or []),
        })
    # Sort by category then name
    result.sort(key=lambda p: (p["category"], p["name"]))
    return {"plugins": result}


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

    asset_id = body.get("asset_id")
    if asset_id is not None:
        try:
            asset_id = int(asset_id)
        except (TypeError, ValueError):
            raise HTTPException(400, "asset_id must be an integer")
        # Validate asset belongs to workspace
        asset_row = (
            db.query(models.Asset)
            .filter(models.Asset.workspace_id == user["ws"], models.Asset.id == asset_id)
            .first()
        )
        if not asset_row:
            raise HTTPException(400, "asset_id does not match a folder in this workspace")

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

    # Per-job Web Authentication override (set from the New Scan dialog).
    # Stored in meta_json under 'web_auth' so the worker can merge it into the
    # profile's options at scan time and auto-enable the web.auth plugin.
    web_auth_override = body.get("web_auth")
    web_auth_ephemeral = bool(body.get("web_auth_credential_ephemeral"))
    meta_payload: dict = {}
    if web_auth_override and isinstance(web_auth_override, dict) and web_auth_override.get("type"):
        if web_auth_override["type"] not in ("form", "bearer", "basic", "cookie", "header"):
            raise HTTPException(400, f"Invalid web_auth type: {web_auth_override['type']}")
        meta_payload["web_auth"] = web_auth_override
        # Ephemeral credentials: the worker deletes the linked credential after the scan
        # ends (any status). Only valid when web_auth references a credential_id.
        if web_auth_ephemeral and web_auth_override.get("credential_id"):
            meta_payload["web_auth_credential_ephemeral"] = True
    # Non-intrusive mode skips plugins flagged PluginMeta.intrusive. Only
    # recorded when the caller chose; absent means intrusive, as before.
    if "intrusive" in body:
        if not isinstance(body["intrusive"], bool):
            raise HTTPException(400, "intrusive must be true or false")
        meta_payload["intrusive"] = body["intrusive"]
    job_meta = json.dumps(meta_payload) if meta_payload else None

    job = models.ScanJob(
        workspace_id=user["ws"],
        target=target,
        profile_id=prof.id,
        asset_id=asset_id,
        status="queued",
        scan_type=scan_type,
        meta_json=job_meta,
        created_by_user_id=user.get("uid") or _resolve_user_id(db, user),
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    try:
        q = Queue("scans", connection=_redis())
        # RQ timeout = scan budget + 300s headroom for post-processing & DB writes
        rq_timeout = settings.SCAN_JOB_TIMEOUT
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
        "asset_id": job.asset_id,
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
    # Build user lookup for created_by display
    user_ids = {r.created_by_user_id for r in rows if r.created_by_user_id}
    user_map = {}
    if user_ids:
        for u in db.query(models.User).filter(models.User.id.in_(user_ids)).all():
            user_map[u.id] = u.email

    return [
        {
            "id": r.id,
            "target": r.target,
            "profile_id": r.profile_id,
            "asset_id": r.asset_id,
            "status": r.status,
            "scan_type": r.scan_type or "internal",
            "created_by": user_map.get(r.created_by_user_id, "").split("@")[0] if r.created_by_user_id else None,
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

    created_by = None
    if job.created_by_user_id:
        creator = db.query(models.User).filter(models.User.id == job.created_by_user_id).first()
        if creator:
            created_by = creator.email.split("@")[0]

    return {
        "job": {
            "id": job.id,
            "target": job.target,
            "profile_id": job.profile_id,
            "asset_id": job.asset_id,
            "status": job.status,
            "scan_type": job.scan_type or "internal",
            "created_by": created_by,
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
                # cvss_base falls back to a severity-derived baseline so the UI
                # doesn't show "—" for plugin findings that aren't tied to a CVE.
                "cvss_base": f.cvss_base if f.cvss_base is not None else _baseline_cvss(f.severity),
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


@router.post("/jobs/{job_id}/cancel")
def cancel_job(
    job_id: int,
    user=Depends(require_role("admin", "analyst")),
    db: Session = Depends(get_db),
):
    """Cancel a running or queued scan job."""
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
    if job.status not in ("queued", "running"):
        raise HTTPException(400, f"Job is already {job.status}")

    # Set Redis cancel flag — worker checks this each plugin iteration
    r = _redis()
    r.setex(f"scan_cancel:{job_id}", 600, "1")

    # If still queued, cancel immediately
    if job.status == "queued":
        job.status = "cancelled"
        job.meta_json = json.dumps({"cancelled": True, "cancelled_by": user.get("email", "unknown")})
        db.commit()
        logger.info("Cancelled queued job #%d", job_id)
        return {"id": job_id, "status": "cancelled", "message": "Job cancelled (was queued)"}

    # If running, the worker will pick up the cancel flag
    logger.info("Cancel requested for running job #%d", job_id)
    return {"id": job_id, "status": "cancelling", "message": "Cancel signal sent — job will stop after current plugin completes"}


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

    # Delete AI analyses linked to this job
    db.query(models.AiAnalysis).filter(
        models.AiAnalysis.job_id == job_id,
        models.AiAnalysis.workspace_id == ws_id,
    ).delete()

    db.query(models.Finding).filter(
        models.Finding.job_id == job_id,
        models.Finding.workspace_id == ws_id,
    ).delete()

    # Mode B (agent-crafted exploit) jobs have an immutable audit trail in
    # agentic_actions whose FK → scan_jobs.id has no ON DELETE CASCADE. Without
    # clearing it first, db.delete(job) raises IntegrityError → 500.
    db.query(models.AgenticAction).filter(
        models.AgenticAction.job_id == job_id,
        models.AgenticAction.workspace_id == ws_id,
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

    # Upload/config-driven scans keep their input (API spec, IaC archive, repo
    # URL/credential, tracks) in meta_json, which the worker overwrites with
    # progress/summary during the run. Rescan copies only target/profile, so a
    # rescanned job would run with no config — fail cleanly instead with a clear
    # message. Re-run these from the New Scan dialog.
    if (original.scan_type or "") in ("api", "iac", "source_code"):
        raise HTTPException(
            400,
            "Rescan is not available for API / IaC / source-code scans — their "
            "configuration is not retained after the run. Start a new scan from "
            "the New Scan dialog instead.",
        )

    # Agentic jobs: re-run as a FRESH agentic session (same target/provider/mode),
    # never copy the old session state. The plain rescan path would lose
    # agentic_json and, for exploit (no profile), fail with "Profile not found".
    if original.agentic_json:
        try:
            ostate = json.loads(original.agentic_json)
        except Exception:
            ostate = {}
        provider = ostate.get("provider") or ""
        if ostate.get("mode") == "exploit":
            if not settings.ENABLE_AGENTIC_EXPLOIT:
                raise HTTPException(403, "Agentic exploitation is disabled (ENABLE_AGENTIC_EXPLOIT off).")
            from app.ai.exploit_guard import target_host, check_target_allowed
            allowed, why = check_target_allowed(db, user["ws"], target_host(original.target))
            if not allowed:
                raise HTTPException(403, f"Target not permitted for exploitation: {why}")
            new_state = {"mode": "exploit", "phase": "run", "provider": provider,
                         "kill": False, "action_count": 0, "seq": 0,
                         "scope_acknowledged_by": user.get("email") or user.get("uid")}
            task_name = "exploit"
        else:
            new_state = {"phase": "plan", "provider": provider, "mode": "plugin"}
            task_name = "plan"

        ag_job = models.ScanJob(
            workspace_id=user["ws"], target=original.target,
            profile_id=original.profile_id, status="queued",
            scan_type=original.scan_type or "external",
            created_by_user_id=user.get("uid") or _resolve_user_id(db, user),
            agentic_json=json.dumps(new_state),
        )
        db.add(ag_job)
        db.commit()
        db.refresh(ag_job)
        try:
            q = Queue("scans", connection=_redis())
            if task_name == "exploit":
                from app.worker_tasks import run_agentic_exploit
                q.enqueue(run_agentic_exploit, ag_job.id, job_timeout=settings.SCAN_JOB_TIMEOUT)
            else:
                q.enqueue(run_scan_job, ag_job.id, job_timeout=settings.SCAN_JOB_TIMEOUT)
        except Exception as e:
            ag_job.status = "failed"
            db.commit()
            raise HTTPException(503, f"Could not enqueue agentic rescan: {e}")
        return {"id": ag_job.id, "original_job_id": job_id, "target": ag_job.target,
                "status": "queued", "agentic": True}

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
        rq_timeout = settings.SCAN_JOB_TIMEOUT
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


# ─── Agentic plugin-orchestration scans (Mode A) ───────────────────────────────

@router.post("/agentic/jobs")
def create_agentic_job(
    body: dict,
    user=Depends(require_role("admin", "analyst")),
    db: Session = Depends(get_db),
):
    """Start an agentic scan: a non-intrusive recon runs, then the AI provider
    proposes a plugin plan and the job pauses at 'awaiting_approval'. Nothing
    intrusive runs until the plan is approved."""
    target = (body.get("target") or "").strip()
    if not target:
        raise HTTPException(400, "target is required")
    provider = (body.get("provider") or "").strip()
    if not provider:
        raise HTTPException(400, "provider is required for an agentic scan")

    scan_type = body.get("scan_type", "internal")
    if scan_type not in ("internal", "external"):
        scan_type = "internal"

    profile_id = body.get("profile_id")
    prof = None
    if profile_id:
        try:
            prof = db.query(models.Profile).filter(
                models.Profile.workspace_id == user["ws"],
                models.Profile.id == int(profile_id),
            ).first()
        except (TypeError, ValueError):
            raise HTTPException(400, "profile_id must be an integer")
    if prof is None:
        prof = (db.query(models.Profile)
                .filter(models.Profile.workspace_id == user["ws"])
                .order_by(models.Profile.id).first())
    if prof is None:
        raise HTTPException(400, "No scan profile available — create one first")

    job = models.ScanJob(
        workspace_id=user["ws"],
        target=target,
        profile_id=prof.id,
        status="queued",
        scan_type=scan_type,
        created_by_user_id=user.get("uid") or _resolve_user_id(db, user),
        agentic_json=json.dumps({"phase": "plan", "provider": provider, "mode": "plugin"}),
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    try:
        q = Queue("scans", connection=_redis())
        q.enqueue(run_scan_job, job.id, job_timeout=settings.SCAN_JOB_TIMEOUT)
        logger.info("Agentic scan job #%d queued (plan phase) target=%s provider=%s",
                    job.id, target, provider)
    except Exception as e:
        job.status = "failed"
        job.meta_json = json.dumps({"error": f"Failed to enqueue: {e}"})
        db.commit()
        raise HTTPException(503, f"Could not enqueue job: {e}")

    return {"id": job.id, "target": target, "status": "queued", "phase": "plan"}


def _load_agentic(db: Session, ws: int, job_id: int) -> tuple[models.ScanJob, dict]:
    job = db.query(models.ScanJob).filter(
        models.ScanJob.workspace_id == ws, models.ScanJob.id == job_id).first()
    if not job:
        raise HTTPException(404, "job not found")
    if not job.agentic_json:
        raise HTTPException(400, "not an agentic job")
    try:
        state = json.loads(job.agentic_json)
    except Exception:
        raise HTTPException(400, "agentic state unreadable")
    return job, state


@router.get("/jobs/{job_id}/plan")
def get_agentic_plan(
    job_id: int,
    user=Depends(require_role("admin", "analyst", "viewer")),
    db: Session = Depends(get_db),
):
    """The proposed plugin plan (and status) for an agentic job."""
    job, state = _load_agentic(db, user["ws"], job_id)
    return {"id": job.id, "status": job.status, "target": job.target, **state}


@router.post("/jobs/{job_id}/approve-plan")
def approve_agentic_plan(
    job_id: int,
    body: dict,
    user=Depends(require_role("admin", "analyst")),
    db: Session = Depends(get_db),
):
    """Approve the proposed plan (optionally a subset of plugin_ids) and run it."""
    job, state = _load_agentic(db, user["ws"], job_id)
    if job.status != "awaiting_approval":
        raise HTTPException(409, f"job is not awaiting approval (status={job.status})")

    proposed = [p["plugin_id"] for p in (state.get("plan") or []) if p.get("plugin_id")]
    requested = body.get("approved_plugins")
    if requested is None:
        approved = proposed                      # approve the whole plan
    else:
        if not isinstance(requested, list):
            raise HTTPException(400, "approved_plugins must be a list of plugin_ids")
        approved = [p for p in requested if p in proposed]  # only from the proposal
    if not approved:
        raise HTTPException(400, "no plugins approved — nothing to run (use reject to cancel)")

    state["phase"] = "execute"
    state["approved_plugins"] = approved
    state["approved_by"] = user.get("email") or user.get("uid")
    job.agentic_json = json.dumps(state)
    job.status = "queued"
    job.finished_at = None
    db.commit()

    try:
        q = Queue("scans", connection=_redis())
        q.enqueue(run_scan_job, job.id, job_timeout=settings.SCAN_JOB_TIMEOUT)
        logger.info("Agentic job #%d approved: %d plugin(s) → execute", job.id, len(approved))
    except Exception as e:
        job.status = "failed"
        db.commit()
        raise HTTPException(503, f"Could not enqueue execution: {e}")

    return {"id": job.id, "status": "queued", "approved_plugins": approved}


@router.post("/jobs/{job_id}/reject-plan")
def reject_agentic_plan(
    job_id: int,
    user=Depends(require_role("admin", "analyst")),
    db: Session = Depends(get_db),
):
    """Reject the plan and cancel the agentic job."""
    job, state = _load_agentic(db, user["ws"], job_id)
    if job.status != "awaiting_approval":
        raise HTTPException(409, f"job is not awaiting approval (status={job.status})")
    state["phase"] = "rejected"
    job.agentic_json = json.dumps(state)
    job.status = "cancelled"
    job.finished_at = datetime.now(timezone.utc)
    db.commit()
    return {"id": job.id, "status": "cancelled"}


# ─── Agentic EXPLOIT (Mode B: agent crafts payloads, per-action approval) ───────

@router.post("/exploit/jobs")
def create_exploit_job(
    body: dict,
    user=Depends(require_role("admin", "analyst")),
    db: Session = Depends(get_db),
):
    """Start a Mode B exploit session. Gated by the ENABLE_AGENTIC_EXPLOIT master
    switch, a fail-closed exploit allowlist, and an explicit scope acknowledgement.
    Every attacking action still needs per-action approval afterwards."""
    if not settings.ENABLE_AGENTIC_EXPLOIT:
        raise HTTPException(403, "Agentic exploitation is disabled. Set ENABLE_AGENTIC_EXPLOIT=true in .env (server-side) to enable it.")
    target = (body.get("target") or "").strip()
    if not target:
        raise HTTPException(400, "target is required")
    provider = (body.get("provider") or "").strip()
    if not provider:
        raise HTTPException(400, "provider is required")
    if not body.get("scope_acknowledged"):
        raise HTTPException(400, "scope_acknowledged must be true — confirm you are authorised to actively test this target")

    from app.ai.exploit_guard import target_host, check_target_allowed
    host = target_host(target)
    allowed, reason = check_target_allowed(db, user["ws"], host)
    if not allowed:
        raise HTTPException(403, f"Target not permitted for exploitation: {reason}")

    scan_type = body.get("scan_type", "external")
    if scan_type not in ("internal", "external"):
        scan_type = "external"

    job = models.ScanJob(
        workspace_id=user["ws"],
        target=target,
        profile_id=None,
        status="queued",
        scan_type=scan_type,
        created_by_user_id=user.get("uid") or _resolve_user_id(db, user),
        agentic_json=json.dumps({
            "mode": "exploit", "phase": "run", "provider": provider,
            "kill": False, "action_count": 0, "seq": 0,
            "scope_acknowledged_by": user.get("email") or user.get("uid"),
        }),
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    try:
        q = Queue("scans", connection=_redis())
        from app.worker_tasks import run_agentic_exploit
        q.enqueue(run_agentic_exploit, job.id, job_timeout=settings.SCAN_JOB_TIMEOUT)
        logger.warning("EXPLOIT session #%d started target=%s host=%s by=%s",
                       job.id, target, host, user.get("email") or user.get("uid"))
    except Exception as e:
        job.status = "failed"
        db.commit()
        raise HTTPException(503, f"Could not enqueue exploit session: {e}")

    return {"id": job.id, "target": target, "status": "queued", "host": host}


@router.get("/jobs/{job_id}/action")
def get_pending_action(
    job_id: int,
    user=Depends(require_role("admin", "analyst", "viewer")),
    db: Session = Depends(get_db),
):
    """The pending (awaiting-approval) action + session info for an exploit job."""
    job, state = _load_agentic(db, user["ws"], job_id)
    return {
        "id": job.id, "status": job.status, "target": job.target,
        "phase": state.get("phase"), "action_count": state.get("action_count", 0),
        "kill": state.get("kill", False),
        "pending": state.get("pending"), "summary": state.get("summary"),
    }


@router.get("/jobs/{job_id}/actions")
def list_exploit_actions(
    job_id: int,
    user=Depends(require_role("admin", "analyst", "viewer")),
    db: Session = Depends(get_db),
):
    """Audit trail of all proposed actions for an exploit job."""
    rows = (db.query(models.AgenticAction)
            .filter(models.AgenticAction.workspace_id == user["ws"],
                    models.AgenticAction.job_id == job_id)
            .order_by(models.AgenticAction.seq).all())
    return {"actions": [{
        "seq": r.seq, "tool": r.tool, "target_host": r.target_host,
        "payload": _safe_json(r.payload_json), "rationale": r.rationale,
        "validation_verdict": r.validation_verdict, "validation_reason": r.validation_reason,
        "decision": r.decision, "approver": r.approver, "reject_reason": r.reject_reason,
        "response_summary": r.response_summary,
        "created_at": r.created_at.isoformat() if r.created_at else None,
        "decided_at": r.decided_at.isoformat() if r.decided_at else None,
    } for r in rows]}


def _safe_json(s):
    try:
        return json.loads(s)
    except Exception:
        return {}


def _decide_action(db, ws, job_id, approve: bool, approver: str, reason: str | None):
    job, state = _load_agentic(db, ws, job_id)
    if state.get("mode") != "exploit":
        raise HTTPException(400, "not an exploit job")
    if job.status != "awaiting_action":
        raise HTTPException(409, f"no action awaiting approval (status={job.status})")
    pending = state.get("pending")
    if not pending:
        raise HTTPException(409, "no pending action")

    pending["decision"] = "approved" if approve else "rejected"
    if not approve:
        pending["reject_reason"] = (reason or "")[:1000]
    state["pending"] = pending
    job.agentic_json = json.dumps(state)
    job.status = "queued"
    job.finished_at = None

    row = db.query(models.AgenticAction).filter(
        models.AgenticAction.id == pending.get("action_id")).first()
    if row:
        row.decision = "approved" if approve else "rejected"
        row.approver = approver
        row.reject_reason = (reason or None) if not approve else None
        row.decided_at = datetime.now(timezone.utc)
    db.commit()

    try:
        q = Queue("scans", connection=_redis())
        from app.worker_tasks import run_agentic_exploit
        q.enqueue(run_agentic_exploit, job_id, job_timeout=settings.SCAN_JOB_TIMEOUT)
    except Exception as e:
        raise HTTPException(503, f"Could not resume session: {e}")
    return {"id": job_id, "status": "queued", "decision": pending["decision"]}


@router.post("/jobs/{job_id}/approve-action")
def approve_action(
    job_id: int,
    user=Depends(require_role("admin", "analyst")),
    db: Session = Depends(get_db),
):
    """Approve the pending exploit action — it runs, then the agent resumes."""
    return _decide_action(db, user["ws"], job_id, True,
                          user.get("email") or str(user.get("uid")), None)


@router.post("/jobs/{job_id}/reject-action")
def reject_action(
    job_id: int,
    body: dict = None,
    user=Depends(require_role("admin", "analyst")),
    db: Session = Depends(get_db),
):
    """Reject the pending action (it is never sent); the agent is told and resumes."""
    reason = (body or {}).get("reason", "")
    return _decide_action(db, user["ws"], job_id, False,
                          user.get("email") or str(user.get("uid")), reason)


@router.post("/jobs/{job_id}/kill")
def kill_exploit(
    job_id: int,
    user=Depends(require_role("admin", "analyst")),
    db: Session = Depends(get_db),
):
    """Kill switch — stop the whole exploit session immediately."""
    job, state = _load_agentic(db, user["ws"], job_id)
    state["kill"] = True
    if job.status == "awaiting_action":
        # paused jobs won't re-run on their own — finalize now
        state["phase"] = "killed"
        job.status = "killed"
        job.finished_at = datetime.now(timezone.utc)
    job.agentic_json = json.dumps(state)
    db.commit()
    logger.warning("EXPLOIT session #%d killed by %s", job_id, user.get("email") or user.get("uid"))
    return {"id": job_id, "status": job.status, "killed": True}


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
            "intrusive": r.intrusive is not False,
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

    intrusive = body.get("intrusive", True)
    if not isinstance(intrusive, bool):
        raise HTTPException(400, "intrusive must be true or false")

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
        intrusive=intrusive,
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

