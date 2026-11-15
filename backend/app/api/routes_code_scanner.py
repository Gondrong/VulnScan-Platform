"""
Source-code Scanner Routes — launch agentic + SCA scans over a codebase.

Input sources:
  • zip  — an uploaded archive of the source tree
  • git  — a remote URL (GitHub / GitLab / Bitbucket / any https or ssh repo),
           optionally with a credential selected from the vault for private repos

The upload is written to disk under /data/code/<job>/ (never base64'd into the
DB row — a repo archive is far too large for that). For git, only the
credential_id is stored in meta_json; the worker re-resolves and decrypts the
secret in memory at clone time, so no plaintext token/key is persisted.
"""
import json
import logging
import os

import redis
from rq import Queue
from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_role
from app.core.config import settings
from app.db import models

logger = logging.getLogger("vulnscan.api.code_scanner")
router = APIRouter(prefix="/scan/code", tags=["code-scanner"])

_MAX_UPLOAD_BYTES = int(os.environ.get("CODE_SCAN_MAX_UPLOAD_BYTES", str(50 * 1024 * 1024)))  # 50 MB
_CODE_ROOT = os.environ.get("CODE_SCAN_ROOT", "/data/code")
_VALID_TRACKS = {"sca", "agent"}


def _parse_tracks(raw: str) -> list[str]:
    tracks = [t.strip().lower() for t in (raw or "").split(",") if t.strip()]
    tracks = [t for t in tracks if t in _VALID_TRACKS]
    return tracks or ["sca", "agent"]


def _resolve_auth(db: Session, ws_id: int, credential_id):
    from app.scanner.code_scan.credentials import resolve_auth
    return resolve_auth(ws_id, credential_id)


@router.post("/preflight")
def preflight(
    git_url: str = Form(...),
    credential_id: int | None = Form(None),
    user=Depends(require_role("admin", "analyst")),
    db: Session = Depends(get_db),
):
    """Check a git remote before launching: reachable? public? credential valid?

    Returns {status, message} where status is one of:
      ok | credential_required | credential_rejected | unreachable
    """
    from app.scanner.code_scan import ingest

    auth = _resolve_auth(db, user["ws"], credential_id) if credential_id else None
    if credential_id and auth is None:
        return {"status": "credential_rejected",
                "message": "Selected credential not found in this workspace."}
    status, message = ingest.preflight_git(git_url, auth)
    return {"status": status, "message": message, "has_credential": bool(auth)}


@router.post("/jobs")
async def create_code_scan_job(
    source_type: str = Form(...),               # "zip" | "git"
    git_url: str = Form(""),
    credential_id: int | None = Form(None),
    provider: str = Form(""),                   # agentic track, e.g. "db:7"
    tracks: str = Form("sca,agent"),
    config_json: str = Form("{}"),
    upload: UploadFile | None = File(None),
    user=Depends(require_role("admin", "analyst")),
    db: Session = Depends(get_db),
):
    stype = (source_type or "").lower()
    if stype not in ("zip", "git"):
        raise HTTPException(400, "source_type must be 'zip' or 'git'")
    track_list = _parse_tracks(tracks)

    try:
        extra_config = json.loads(config_json or "{}")
    except json.JSONDecodeError:
        raise HTTPException(400, "config_json is not valid JSON")

    # ── git source: validate + preflight credential so the user gets an
    #    immediate "needs credential / invalid / ok" answer, not a late failure.
    if stype == "git":
        if not git_url or not git_url.startswith(("http://", "https://", "git@", "ssh://")):
            raise HTTPException(400, "git_url must be an http(s) or ssh git URL")
        from app.scanner.code_scan import ingest
        auth = _resolve_auth(db, user["ws"], credential_id) if credential_id else None
        if credential_id and auth is None:
            raise HTTPException(400, "Selected credential not found in this workspace")
        status, message = ingest.preflight_git(git_url, auth)
        if status != "ok":
            # 409 = the request was well-formed but the source isn't ready to scan
            raise HTTPException(409, json.dumps({"preflight": status, "message": message}))
        label = git_url
        source = {"type": "git", "ref": git_url, "credential_id": credential_id}
        upload_bytes = 0
        filename = None
    else:
        # ── zip source: read upload (bounded), store to disk after job id known
        if upload is None:
            raise HTTPException(400, "source_type 'zip' requires an uploaded archive")
        raw = await upload.read()
        if len(raw) > _MAX_UPLOAD_BYTES:
            raise HTTPException(413, f"Upload exceeds {_MAX_UPLOAD_BYTES // (1024*1024)} MB limit")
        if not raw:
            raise HTTPException(400, "Uploaded archive is empty")
        filename = upload.filename or "archive.zip"
        label = f"code://{filename}"
        upload_bytes = len(raw)
        source = {"type": "zip", "filename": filename}  # ref filled after job id

    # ── create the job row ──────────────────────────────────────────────────
    job = models.ScanJob(
        workspace_id=user["ws"],
        target=label[:512],
        profile_id=None,
        status="queued",
        scan_type="source_code",
        created_by_user_id=user.get("id"),
        meta_json=json.dumps({
            "code_scanner_config": {
                "source": source,
                "provider": provider or None,
                "tracks": track_list,
                **({k: v for k, v in extra_config.items() if k not in ("source", "tracks")}),
            },
            "filename": filename,
            "size_bytes": upload_bytes,
            "source_type": stype,
            "tracks": track_list,
        }),
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    # ── for zip, write the archive to the job's working dir and record its ref
    if stype == "zip":
        workdir = os.path.join(_CODE_ROOT, str(job.id))
        try:
            os.makedirs(workdir, exist_ok=True)
            archive_path = os.path.join(workdir, "_upload.zip")
            with open(archive_path, "wb") as f:
                f.write(raw)
        except OSError as e:
            job.status = "failed"
            job.meta_json = json.dumps({"error": f"Could not store upload: {e}"})
            db.commit()
            raise HTTPException(500, f"Could not store upload: {e}")
        meta = json.loads(job.meta_json)
        meta["code_scanner_config"]["source"]["ref"] = archive_path
        job.meta_json = json.dumps(meta)
        db.commit()

    # ── enqueue ─────────────────────────────────────────────────────────────
    try:
        redis_conn = redis.from_url(settings.REDIS_URL)
        q = Queue("scans", connection=redis_conn)
        from app.worker_tasks import run_scan_job
        q.enqueue(run_scan_job, job.id, job_timeout=settings.CODE_SCAN_JOB_TIMEOUT)
        logger.info("Code scan job #%d queued: source=%s tracks=%s", job.id, stype, track_list)
    except Exception as e:
        job.status = "failed"
        job.meta_json = json.dumps({"error": str(e)})
        db.commit()
        raise HTTPException(503, f"Could not enqueue job: {e}")

    return {
        "id": job.id,
        "target": label,
        "status": "queued",
        "scan_type": "source_code",
        "source_type": stype,
        "tracks": track_list,
        "filename": filename,
        "size_bytes": upload_bytes,
    }
