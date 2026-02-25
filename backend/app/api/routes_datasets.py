from fastapi import APIRouter, Depends, HTTPException
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
    db.delete(d)
    db.commit()
    return {"ok": True}
