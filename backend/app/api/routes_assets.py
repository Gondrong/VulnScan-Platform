import json
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_role
from app.db import models

logger = logging.getLogger("vulnscan.assets")

router = APIRouter(prefix="/assets", tags=["assets"])


class AssetCreate(BaseModel):
    name: str
    description: str | None = ""
    parent_id: int | None = None
    owner: str | None = ""
    default_profile_id: int | None = None
    default_credential_id: int | None = None
    tags: list[str] | None = None
    sla_overrides: dict | None = None


class AssetUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    parent_id: int | None = None
    owner: str | None = None
    default_profile_id: int | None = None
    default_credential_id: int | None = None
    tags: list[str] | None = None
    sla_overrides: dict | None = None


def _serialize(a: models.Asset, db: Session) -> dict:
    """Serialize an asset with computed rollups (severity counts, last_scan, risk)."""
    ws = a.workspace_id
    # Severity counts from findings of jobs in this asset
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    last_scan_at = None
    target_set = set()
    risk_max = 0.0

    job_rows = (
        db.query(models.ScanJob)
        .filter(models.ScanJob.workspace_id == ws, models.ScanJob.asset_id == a.id)
        .all()
    )
    for j in job_rows:
        target_set.add(j.target)
        if j.created_at and (last_scan_at is None or j.created_at > last_scan_at):
            last_scan_at = j.created_at

    if job_rows:
        job_ids = [j.id for j in job_rows]
        findings = (
            db.query(models.Finding)
            .filter(models.Finding.workspace_id == ws, models.Finding.job_id.in_(job_ids))
            .all()
        )
        for f in findings:
            if f.severity in sev_counts:
                sev_counts[f.severity] += 1
            if f.risk_score and f.risk_score > risk_max:
                risk_max = f.risk_score

    try:
        tags = json.loads(a.tags_json or "[]")
    except Exception:
        tags = []
    try:
        sla = json.loads(a.sla_overrides_json) if a.sla_overrides_json else None
    except Exception:
        sla = None

    return {
        "id": a.id,
        "name": a.name,
        "description": a.description,
        "parent_id": a.parent_id,
        "owner": a.owner,
        "default_profile_id": a.default_profile_id,
        "default_credential_id": a.default_credential_id,
        "tags": tags,
        "sla_overrides": sla,
        "created_at": a.created_at.isoformat() if a.created_at else None,
        # Rollups
        "targets": len(target_set),
        "scans": len(job_rows),
        "critical": sev_counts["critical"],
        "high":     sev_counts["high"],
        "medium":   sev_counts["medium"],
        "low":      sev_counts["low"],
        "info":     sev_counts["info"],
        "risk":     round(risk_max, 1) if risk_max else 0,
        "last_scan_at": last_scan_at.isoformat() if last_scan_at else None,
    }


@router.get("")
def list_assets(
    user=Depends(require_role("admin", "analyst", "viewer")),
    db: Session = Depends(get_db),
):
    """List all assets for the workspace, with rollups."""
    assets = (
        db.query(models.Asset)
        .filter(models.Asset.workspace_id == user["ws"])
        .order_by(models.Asset.name)
        .all()
    )
    return [_serialize(a, db) for a in assets]


@router.post("")
def create_asset(
    body: AssetCreate,
    user=Depends(require_role("admin", "analyst")),
    db: Session = Depends(get_db),
):
    if not body.name or not body.name.strip():
        raise HTTPException(400, "Name is required")

    if body.parent_id is not None:
        parent = db.query(models.Asset).filter(
            models.Asset.workspace_id == user["ws"],
            models.Asset.id == body.parent_id,
        ).first()
        if not parent:
            raise HTTPException(400, "Parent asset not found")

    a = models.Asset(
        workspace_id=user["ws"],
        name=body.name.strip(),
        description=body.description or "",
        parent_id=body.parent_id,
        owner=body.owner or "",
        default_profile_id=body.default_profile_id,
        default_credential_id=body.default_credential_id,
        tags_json=json.dumps(body.tags or []),
        sla_overrides_json=json.dumps(body.sla_overrides) if body.sla_overrides else None,
    )
    db.add(a)
    db.commit()
    db.refresh(a)
    logger.info("Asset #%d created: %s", a.id, a.name)
    return _serialize(a, db)


@router.patch("/{asset_id}")
def update_asset(
    asset_id: int,
    body: AssetUpdate,
    user=Depends(require_role("admin", "analyst")),
    db: Session = Depends(get_db),
):
    a = db.query(models.Asset).filter(
        models.Asset.workspace_id == user["ws"],
        models.Asset.id == asset_id,
    ).first()
    if not a:
        raise HTTPException(404, "Asset not found")

    data = body.dict(exclude_unset=True)
    if "name" in data and data["name"]:
        a.name = data["name"].strip()
    if "description" in data:
        a.description = data["description"] or ""
    if "parent_id" in data:
        if data["parent_id"] == asset_id:
            raise HTTPException(400, "Asset cannot be its own parent")
        a.parent_id = data["parent_id"]
    if "owner" in data:
        a.owner = data["owner"] or ""
    if "default_profile_id" in data:
        a.default_profile_id = data["default_profile_id"]
    if "default_credential_id" in data:
        a.default_credential_id = data["default_credential_id"]
    if "tags" in data:
        a.tags_json = json.dumps(data["tags"] or [])
    if "sla_overrides" in data:
        a.sla_overrides_json = json.dumps(data["sla_overrides"]) if data["sla_overrides"] else None

    db.commit()
    db.refresh(a)
    return _serialize(a, db)


@router.delete("/{asset_id}")
def delete_asset(
    asset_id: int,
    user=Depends(require_role("admin", "analyst")),
    db: Session = Depends(get_db),
):
    a = db.query(models.Asset).filter(
        models.Asset.workspace_id == user["ws"],
        models.Asset.id == asset_id,
    ).first()
    if not a:
        raise HTTPException(404, "Asset not found")

    # Reparent children to this asset's parent (or top-level)
    db.query(models.Asset).filter(
        models.Asset.workspace_id == user["ws"],
        models.Asset.parent_id == asset_id,
    ).update({models.Asset.parent_id: a.parent_id}, synchronize_session="fetch")

    # Unlink jobs
    db.query(models.ScanJob).filter(
        models.ScanJob.workspace_id == user["ws"],
        models.ScanJob.asset_id == asset_id,
    ).update({models.ScanJob.asset_id: None}, synchronize_session="fetch")

    db.delete(a)
    db.commit()
    return {"ok": True, "deleted_asset_id": asset_id}


@router.get("/{asset_id}")
def asset_detail(
    asset_id: int,
    user=Depends(require_role("admin", "analyst", "viewer")),
    db: Session = Depends(get_db),
):
    a = db.query(models.Asset).filter(
        models.Asset.workspace_id == user["ws"],
        models.Asset.id == asset_id,
    ).first()
    if not a:
        raise HTTPException(404, "Asset not found")
    return _serialize(a, db)


@router.get("/{asset_id}/jobs")
def asset_jobs(
    asset_id: int,
    user=Depends(require_role("admin", "analyst", "viewer")),
    db: Session = Depends(get_db),
):
    """All scan jobs tagged with this asset."""
    rows = (
        db.query(models.ScanJob)
        .filter(
            models.ScanJob.workspace_id == user["ws"],
            models.ScanJob.asset_id == asset_id,
        )
        .order_by(models.ScanJob.created_at.desc())
        .all()
    )
    return [
        {
            "id": j.id,
            "target": j.target,
            "profile_id": j.profile_id,
            "status": j.status,
            "scan_type": j.scan_type or "internal",
            "created_at": j.created_at.isoformat() if j.created_at else None,
            "finished_at": j.finished_at.isoformat() if j.finished_at else None,
        }
        for j in rows
    ]


@router.get("/{asset_id}/targets")
def asset_targets(
    asset_id: int,
    user=Depends(require_role("admin", "analyst", "viewer")),
    db: Session = Depends(get_db),
):
    """Distinct targets in this asset, with last-scan + finding count."""
    rows = (
        db.query(models.ScanJob)
        .filter(
            models.ScanJob.workspace_id == user["ws"],
            models.ScanJob.asset_id == asset_id,
        )
        .all()
    )
    by_target: dict[str, dict] = {}
    for j in rows:
        slot = by_target.setdefault(j.target, {
            "target": j.target,
            "scans": 0,
            "last_scan_at": None,
            "findings": 0,
        })
        slot["scans"] += 1
        if j.created_at and (slot["last_scan_at"] is None or j.created_at > slot["last_scan_at"]):
            slot["last_scan_at"] = j.created_at

    if rows:
        job_ids = [j.id for j in rows]
        f_rows = (
            db.query(models.Finding.job_id, models.Finding.target)
            .filter(
                models.Finding.workspace_id == user["ws"],
                models.Finding.job_id.in_(job_ids),
            )
            .all()
        )
        # group findings count by target — match via job lookup
        job_to_target = {j.id: j.target for j in rows}
        for jid, _t in f_rows:
            t = job_to_target.get(jid)
            if t and t in by_target:
                by_target[t]["findings"] += 1

    out = []
    for slot in by_target.values():
        out.append({
            **slot,
            "last_scan_at": slot["last_scan_at"].isoformat() if slot["last_scan_at"] else None,
        })
    out.sort(key=lambda x: x["target"])
    return out
