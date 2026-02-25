import json
import os
import shutil
import uuid

from fastapi import APIRouter, Depends, HTTPException, File, Query, UploadFile
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.auth import require_auth
from app.db.session import get_db
from app.db import models

router = APIRouter(prefix="/datasets", tags=["datasets"])


class DatasetCreate(BaseModel):
    name: str
    kind: str
    path: str
    enabled: bool = True


@router.get("")
def list_datasets(claims=Depends(require_auth), db: Session = Depends(get_db)):
    ws = claims["ws"]
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
    body: DatasetCreate, claims=Depends(require_auth), db: Session = Depends(get_db)
):
    ws = claims["ws"]
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


# FIX: Add file upload endpoint — the frontend and bootstrap.sh call POST /datasets/upload
@router.post("/upload")
async def upload_dataset(
    file: UploadFile = File(...),
    kind: str = Query(...),
    name: str = Query(""),
    claims: dict = Depends(require_auth),
    db: Session = Depends(get_db),
):
    ws = claims["ws"]
    if not name:
        name = kind

    # Validate the file is JSON
    content = await file.read()
    try:
        json.loads(content)
    except Exception:
        raise HTTPException(400, "File is not valid JSON")

    # Save to disk
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
    claims=Depends(require_auth),
    db: Session = Depends(get_db),
):
    ws = claims["ws"]
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


# FIX: Add toggle endpoint for enabling/disabling datasets from the UI
@router.patch("/{ds_id}/toggle")
def toggle_dataset(
    ds_id: int,
    claims=Depends(require_auth),
    db: Session = Depends(get_db),
):
    ws = claims["ws"]
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
    ds_id: int, claims=Depends(require_auth), db: Session = Depends(get_db)
):
    ws = claims["ws"]
    d = (
        db.query(models.CveDataset)
        .filter(models.CveDataset.id == ds_id, models.CveDataset.workspace_id == ws)
        .first()
    )
    if not d:
        raise HTTPException(status_code=404, detail="Not found")

    # Optionally remove the file from disk
    if d.path and os.path.isfile(d.path):
        try:
            os.remove(d.path)
        except Exception:
            pass

    db.delete(d)
    db.commit()
    return {"ok": True}
