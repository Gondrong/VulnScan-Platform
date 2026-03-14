"""
Credential management API routes.
Stores SSH keys and passwords encrypted with Fernet (via crypto.py).
"""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_role
from app.core.crypto import encrypt_str
from app.db import models

router = APIRouter(prefix="/credentials", tags=["credentials"])


class CredCreate(BaseModel):
    name: str
    kind: str = "ssh"
    username: str
    secret: str
    secret_type: str = "password"  # password | ssh_key
    passphrase: str | None = None


@router.get("")
def list_creds(user=Depends(require_role("admin", "analyst", "viewer")), db: Session = Depends(get_db)):
    ws = user["ws"]
    creds = (
        db.query(models.Credential)
        .filter(models.Credential.workspace_id == ws)
        .all()
    )
    return [
        {
            "id": c.id,
            "name": c.name,
            "kind": c.kind,
            "username": c.username,
            "secret_type": c.secret_type,
        }
        for c in creds
    ]


@router.post("")
def create_cred(
    body: CredCreate,
    user=Depends(require_role("admin", "analyst")),
    db: Session = Depends(get_db),
):
    ws = user["ws"]

    if not body.secret or not body.secret.strip():
        raise HTTPException(400, "Secret (key or password) is required")

    c = models.Credential(
        workspace_id=ws,
        name=body.name,
        kind=body.kind,
        username=body.username,
        secret_enc=encrypt_str(body.secret),
        secret_type=body.secret_type,
        passphrase_enc=encrypt_str(body.passphrase) if body.passphrase else None,
    )
    db.add(c)
    db.commit()
    db.refresh(c)
    return {"id": c.id}


@router.delete("/{cred_id}")
def delete_cred(
    cred_id: int,
    user=Depends(require_role("admin", "analyst")),
    db: Session = Depends(get_db),
):
    ws = user["ws"]
    c = (
        db.query(models.Credential)
        .filter(
            models.Credential.id == cred_id,
            models.Credential.workspace_id == ws,
        )
        .first()
    )
    if not c:
        raise HTTPException(status_code=404, detail="Not found")
    db.delete(c)
    db.commit()
    return {"ok": True}