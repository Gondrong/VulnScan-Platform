"""
IaC Scanner Routes — endpoints for launching Infrastructure-as-Code scans
against uploaded archives or single config files.

Supported input:
  • A single Terraform / Dockerfile / Kubernetes / CloudFormation / compose file
  • A .zip archive containing a mix of the above
"""
import base64
import json
import logging

import redis
from rq import Queue
from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_role
from app.core.config import settings
from app.db import models

logger = logging.getLogger("vulnscan.api.iac_scanner")
router = APIRouter(prefix="/scan/iac", tags=["iac-scanner"])

_MAX_UPLOAD_BYTES = 5 * 1024 * 1024  # 5 MB

_VALID_KINDS = {
    "terraform",
    "dockerfile",
    "kubernetes",
    "compose",
    "cloudformation",
    "helm_values",
}


async def _read_upload(upload: UploadFile) -> bytes:
    data = await upload.read()
    if len(data) > _MAX_UPLOAD_BYTES:
        raise HTTPException(
            413,
            f"Upload exceeds {_MAX_UPLOAD_BYTES // 1024} KB limit",
        )
    return data


@router.post("/parse")
async def parse_iac_upload(
    upload: UploadFile = File(...),
    user=Depends(require_role("admin", "analyst")),
):
    """
    Parse an upload and return a file inventory (preview only — no scan).
    Useful for confirming what the orchestrator will scan before launching.
    """
    from app.scanner.plugins.iac_scanner.parser import parse_upload

    data = await _read_upload(upload)
    files = parse_upload(upload.filename or "upload", data)

    by_kind: dict[str, list[str]] = {}
    for f in files:
        by_kind.setdefault(f.kind, []).append(f.path)

    summary = {kind: len(paths) for kind, paths in by_kind.items()}
    scannable = sum(c for k, c in summary.items() if k in _VALID_KINDS)

    return {
        "filename": upload.filename,
        "size_bytes": len(data),
        "files_total": len(files),
        "files_scannable": scannable,
        "summary": summary,
        "files": [
            {"path": f.path, "kind": f.kind, "bytes": len(f.content)}
            for f in files[:500]
        ],
    }


@router.post("/jobs")
async def create_iac_scan_job(
    upload: UploadFile = File(...),
    config_json: str = Form("{}"),
    user=Depends(require_role("admin", "analyst")),
    db: Session = Depends(get_db),
):
    """
    Create an IaC scanner job.

    config_json (optional):
      {
        "kinds": ["terraform","kubernetes",...]   # filter, default = all supported
      }
    """
    try:
        config = json.loads(config_json or "{}")
    except json.JSONDecodeError:
        raise HTTPException(400, "config_json is not valid JSON")

    requested_kinds = set(config.get("kinds") or [])
    invalid = requested_kinds - _VALID_KINDS
    if invalid:
        raise HTTPException(
            400,
            f"Invalid kinds: {invalid}. Valid: {', '.join(sorted(_VALID_KINDS))}",
        )

    raw = await _read_upload(upload)
    archive_b64 = base64.b64encode(raw).decode("ascii")

    # Stash the upload + config in meta_json — the worker decodes it before
    # the first progress callback overwrites this field
    iac_config = {
        "archive_b64": archive_b64,
        "filename": upload.filename or "upload",
        "kinds": sorted(requested_kinds),
    }

    target_label = f"iac://{upload.filename or 'upload'}"
    job = models.ScanJob(
        workspace_id=user["ws"],
        target=target_label,
        profile_id=None,
        status="queued",
        scan_type="iac",
        meta_json=json.dumps({
            "iac_scanner_config": iac_config,
            "filename": upload.filename,
            "size_bytes": len(raw),
            "kinds": sorted(requested_kinds) or "all",
        }),
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    try:
        redis_conn = redis.from_url(settings.REDIS_URL)
        q = Queue("scans", connection=redis_conn)
        from app.worker_tasks import run_scan_job
        q.enqueue(
            run_scan_job, job.id,
            job_timeout=settings.SCAN_JOB_TIMEOUT,
        )
        logger.info(
            "IaC scan job #%d queued: filename=%s kinds=%s size=%d",
            job.id, upload.filename, requested_kinds or "all", len(raw),
        )
    except Exception as e:
        job.status = "failed"
        job.meta_json = json.dumps({"error": str(e)})
        db.commit()
        raise HTTPException(503, f"Could not enqueue job: {e}")

    return {
        "id": job.id,
        "target": target_label,
        "status": "queued",
        "scan_type": "iac",
        "filename": upload.filename,
        "size_bytes": len(raw),
        "kinds": sorted(requested_kinds) or list(sorted(_VALID_KINDS)),
    }


@router.get("/kinds")
def list_iac_kinds(user=Depends(require_role("admin", "analyst", "viewer"))):
    """List the IaC formats this scanner knows how to check."""
    return {
        "kinds": [
            {"id": "terraform", "name": "Terraform / HCL",
             "extensions": [".tf", ".tfvars"],
             "description": "AWS S3 public ACLs, open security groups, public RDS, hardcoded secrets"},
            {"id": "dockerfile", "name": "Dockerfile",
             "extensions": ["Dockerfile", "*.dockerfile"],
             "description": "Root user, latest tag, ADD-from-URL, secret ENV/ARG, curl|sh"},
            {"id": "kubernetes", "name": "Kubernetes manifests",
             "extensions": [".yaml", ".yml"],
             "description": "Privileged, hostNetwork, runAsRoot, allowPrivilegeEscalation, missing limits"},
            {"id": "compose", "name": "docker-compose",
             "extensions": ["docker-compose.yml", "compose.yml"],
             "description": "Privileged services, host network, docker.sock mount, latest tag"},
            {"id": "cloudformation", "name": "AWS CloudFormation",
             "extensions": [".yaml", ".yml", ".json"],
             "description": "Public S3 buckets, open SGs, public RDS, missing encryption"},
            {"id": "helm_values", "name": "Helm values.yaml",
             "extensions": ["values.yaml"],
             "description": "K8s primitives in chart values (privileged, hostNetwork, runAsUser)"},
        ],
    }
