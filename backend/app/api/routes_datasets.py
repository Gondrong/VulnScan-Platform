import json
import os
import uuid

import redis
from fastapi import APIRouter, Depends, HTTPException, File, Query, UploadFile
from pydantic import BaseModel
from rq import Queue
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_role
from app.core.config import settings
from app.db import models

router = APIRouter(prefix="/datasets", tags=["datasets"])


# ── Browse dataset contents ─────────────────────────────────────────────────

@router.get("/browse/{kind}")
def browse_dataset(
    kind: str,
    q: str = Query("", description="Search filter"),
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    user=Depends(require_role("admin", "analyst", "viewer")),
    db: Session = Depends(get_db),
):
    """Return paginated contents of a dataset file."""
    ws = user["ws"]
    ds = (
        db.query(models.CveDataset)
        .filter(
            models.CveDataset.workspace_id == ws,
            models.CveDataset.kind == kind,
            models.CveDataset.enabled == True,
        )
        .order_by(models.CveDataset.id.desc())
        .first()
    )
    if not ds:
        raise HTTPException(404, f"No enabled dataset of kind '{kind}'")
    if not ds.path or not os.path.isfile(ds.path):
        raise HTTPException(404, f"Dataset file not found: {ds.path}")

    try:
        with open(ds.path, "r", encoding="utf-8") as f:
            raw = json.load(f)
    except Exception as e:
        raise HTTPException(500, f"Failed to read dataset: {e}")

    # Normalize to list of records
    if kind == "cvedetails_cvss":
        # Dict keyed by CVE-ID → convert to list
        records = [{"cve": k, **v} for k, v in raw.items()] if isinstance(raw, dict) else raw
    elif kind == "compliance_map":
        # Has metadata wrapper
        records = raw.get("mappings", []) if isinstance(raw, dict) else raw
    else:
        records = raw if isinstance(raw, list) else []

    # Search filter
    if q:
        ql = q.lower()
        filtered = []
        for r in records:
            if any(ql in str(v).lower() for v in r.values()):
                filtered.append(r)
        records = filtered

    total = len(records)
    start = (page - 1) * per_page
    end = start + per_page
    page_records = records[start:end]

    # For compliance_map, also include control_descriptions and frameworks metadata
    extra = {}
    if kind == "compliance_map" and isinstance(raw, dict):
        extra["control_descriptions"] = raw.get("control_descriptions", {})
        extra["frameworks"] = raw.get("frameworks", [])
        extra["version"] = raw.get("version", "")

    return {
        "kind": kind,
        "total": total,
        "page": page,
        "per_page": per_page,
        "total_pages": max(1, -(-total // per_page)),
        "records": page_records,
        **extra,
    }


class DatasetCreate(BaseModel):
    name: str
    kind: str
    path: str
    enabled: bool = True


@router.get("")
def list_datasets(user=Depends(require_role("admin", "analyst", "viewer")), db: Session = Depends(get_db)):
    ws = user["ws"]
    ds = db.query(models.CveDataset).filter(models.CveDataset.workspace_id == ws).all()
    return [
        {
            "id": d.id,
            "name": d.name,
            "kind": d.kind,
            "path": d.path,
            "enabled": d.enabled,
        }
        for d in ds
    ]


@router.post("")
def create_dataset(
    body: DatasetCreate,
    user=Depends(require_role("admin", "analyst")),
    db: Session = Depends(get_db),
):
    ws = user["ws"]
    d = models.CveDataset(
        workspace_id=ws,
        name=body.name,
        kind=body.kind,
        path=body.path,
        enabled=body.enabled,
    )
    db.add(d)
    db.commit()
    db.refresh(d)
    return {"id": d.id}


@router.post("/upload")
async def upload_dataset(
    file: UploadFile = File(...),
    kind: str = Query(...),
    name: str = Query(""),
    user: dict = Depends(require_role("admin", "analyst")),
    db: Session = Depends(get_db),
):
    ws = user["ws"]
    if not name:
        name = kind

    content = await file.read()
    try:
        json.loads(content)
    except Exception:
        raise HTTPException(400, "File is not valid JSON")

    upload_dir = "/data/cve"
    os.makedirs(upload_dir, exist_ok=True)
    filename = f"{kind}_{uuid.uuid4().hex[:8]}.json"
    filepath = os.path.join(upload_dir, filename)

    with open(filepath, "wb") as f:
        f.write(content)

    d = models.CveDataset(
        workspace_id=ws,
        name=name,
        kind=kind,
        path=filepath,
        enabled=True,
    )
    db.add(d)
    db.commit()
    db.refresh(d)
    return {"dataset_id": d.id, "path": filepath}


@router.patch("/{ds_id}")
def update_dataset(
    ds_id: int,
    body: dict,
    user=Depends(require_role("admin", "analyst")),
    db: Session = Depends(get_db),
):
    ws = user["ws"]
    d = (
        db.query(models.CveDataset)
        .filter(models.CveDataset.id == ds_id, models.CveDataset.workspace_id == ws)
        .first()
    )
    if not d:
        raise HTTPException(status_code=404, detail="Not found")
    for k, v in body.items():
        if hasattr(d, k):
            setattr(d, k, v)
    db.commit()
    return {"ok": True}


@router.patch("/{ds_id}/toggle")
def toggle_dataset(
    ds_id: int,
    user=Depends(require_role("admin", "analyst")),
    db: Session = Depends(get_db),
):
    ws = user["ws"]
    d = (
        db.query(models.CveDataset)
        .filter(models.CveDataset.id == ds_id, models.CveDataset.workspace_id == ws)
        .first()
    )
    if not d:
        raise HTTPException(status_code=404, detail="Not found")
    d.enabled = not d.enabled
    db.commit()
    return {"ok": True, "enabled": d.enabled}


@router.delete("/{ds_id}")
def delete_dataset(
    ds_id: int,
    user=Depends(require_role("admin", "analyst")),
    db: Session = Depends(get_db),
):
    ws = user["ws"]
    d = (
        db.query(models.CveDataset)
        .filter(models.CveDataset.id == ds_id, models.CveDataset.workspace_id == ws)
        .first()
    )
    if not d:
        raise HTTPException(status_code=404, detail="Not found")

    if d.path and os.path.isfile(d.path):
        try:
            os.remove(d.path)
        except Exception:
            pass

    db.delete(d)
    db.commit()
    return {"ok": True}


# ── Dataset Refresh ─────────────────────────────────────────────────────────

_VALID_KINDS = {"nvd_cpe_cve", "cisa_kev", "epss", "cvedetails_cvss", "cms_cve_map", "compliance_map"}


def _redis_conn():
    return redis.Redis.from_url(settings.REDIS_URL)


@router.post("/refresh")
def refresh_datasets(
    body: dict = {},
    user: dict = Depends(require_role("admin")),
):
    from app.worker_tasks import run_dataset_refresh

    ws = user["ws"]
    kinds = None
    if "kind" in body:
        kinds = [body["kind"]]
    elif "kinds" in body:
        kinds = body["kinds"]

    if kinds:
        invalid = set(kinds) - _VALID_KINDS
        if invalid:
            raise HTTPException(400, f"Invalid kinds: {invalid}")

    r = _redis_conn()
    if r.exists(f"dataset_refresh_lock:{ws}"):
        raise HTTPException(409, "A dataset refresh is already running")

    q = Queue("scans", connection=r)
    q.enqueue(run_dataset_refresh, ws, kinds, job_timeout=1800)
    return {"status": "queued", "kinds": kinds or list(_VALID_KINDS)}


@router.get("/refresh/status")
def refresh_status(
    user: dict = Depends(require_role("admin", "analyst", "viewer")),
):
    ws = user["ws"]
    r = _redis_conn()
    data = r.get(f"dataset_refresh:{ws}")
    if not data:
        return {"status": "idle"}
    return json.loads(data)


@router.post("/refresh/cancel")
def cancel_refresh(
    user: dict = Depends(require_role("admin")),
):
    ws = user["ws"]
    r = _redis_conn()
    r.delete(f"dataset_refresh_lock:{ws}")
    data = r.get(f"dataset_refresh:{ws}")
    if data:
        state = json.loads(data)
        state["status"] = "cancelled"
        r.setex(f"dataset_refresh:{ws}", 3600, json.dumps(state))
    return {"ok": True}