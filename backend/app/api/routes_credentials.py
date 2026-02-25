import base64
import os

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.auth import require_auth
from app.db.session import get_db
from app.db import models

router = APIRouter(prefix="/credentials", tags=["credentials"])

# Simple XOR-based encryption placeholder (replace with proper AES-256 in prod)
_KEY = os.environ.get("SECRET_KEY", "changeme")[:32].encode().ljust(32, b"\x00")


def _encrypt(plaintext: str) -> str:
    data = plaintext.encode()
    key = (_KEY * ((len(data) // len(_KEY)) + 1))[: len(data)]
    return base64.b64encode(bytes(a ^ b for a, b in zip(data, key))).decode()


def _decrypt(ciphertext: str) -> str:
    data = base64.b64decode(ciphertext)
    key = (_KEY * ((len(data) // len(_KEY)) + 1))[: len(data)]
    return bytes(a ^ b for a, b in zip(data, key)).decode()


class CredCreate(BaseModel):
    name: str
    kind: str = "ssh"
    username: str
    secret: str
    secret_type: str = "password"
    passphrase: str | None = None


@router.get("")
def list_creds(claims=Depends(require_auth), db: Session = Depends(get_db)):
    ws = claims["ws"]
    creds = db.query(models.Credential).filter(models.Credential.workspace_id == ws).all()
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
    body: CredCreate, claims=Depends(require_auth), db: Session = Depends(get_db)
):
    ws = claims["ws"]
    c = models.Credential(
        workspace_id=ws,
        name=body.name,
        kind=body.kind,
        username=body.username,
        secret_enc=_encrypt(body.secret),
        secret_type=body.secret_type,
        passphrase_enc=_encrypt(body.passphrase) if body.passphrase else None,
    )
    db.add(c)
    db.commit()
    db.refresh(c)
    return {"id": c.id}


@router.delete("/{cred_id}")
def delete_cred(cred_id: int, claims=Depends(require_auth), db: Session = Depends(get_db)):
    ws = claims["ws"]
    c = (
        db.query(models.Credential)
        .filter(models.Credential.id == cred_id, models.Credential.workspace_id == ws)
        .first()
    )
    if not c:
        raise HTTPException(status_code=404, detail="Not found")
    db.delete(c)
    db.commit()
    return {"ok": True}
