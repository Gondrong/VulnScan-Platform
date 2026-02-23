import os
from fastapi import APIRouter, Depends, UploadFile, File, HTTPException
from sqlalchemy.orm import Session
from app.api.deps import get_db, require_role
from app.db import models

router = APIRouter(prefix="/datasets", tags=["datasets"])

@router.get("")
def list_datasets(user=Depends(require_role("admin","analyst","viewer")), db: Session = Depends(get_db)):
    return db.query(models.CveDataset).filter(models.CveDataset.workspace_id==user["workspace_id"]).order_by(models.CveDataset.id.desc()).all()

@router.post("/upload")
async def upload_dataset(
    kind: str,
    name: str,
    file: UploadFile = File(...),
    user=Depends(require_role("admin")),
    db: Session = Depends(get_db)
):
    base = os.path.join("/data/cve", str(user["workspace_id"]))
    os.makedirs(base, exist_ok=True)

    raw = await file.read()
    if len(raw) < 10:
        raise HTTPException(400, "file too small")

    fn = file.filename or f"{kind}.json"
    path = os.path.join(base, fn)
    with open(path, "wb") as f:
        f.write(raw)

    row = models.CveDataset(workspace_id=user["workspace_id"], name=name, kind=kind, path=path, enabled=True)
    db.add(row); db.commit(); db.refresh(row)
    return {"ok": True, "dataset_id": row.id, "path": path}