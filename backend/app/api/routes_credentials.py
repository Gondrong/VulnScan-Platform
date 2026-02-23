from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.api.deps import get_db, require_role
from app.db import models
from app.db.schemas import CredentialIn, CredentialOut
from app.core.crypto import encrypt_str

router = APIRouter(prefix="/credentials", tags=["credentials"])

@router.get("", response_model=list[CredentialOut])
def list_credentials(user=Depends(require_role("admin","analyst","viewer")), db: Session = Depends(get_db)):
    return db.query(models.Credential).filter(models.Credential.workspace_id==user["workspace_id"]).order_by(models.Credential.id.desc()).all()

@router.post("", response_model=CredentialOut)
def create_credential(body: CredentialIn, user=Depends(require_role("admin")), db: Session = Depends(get_db)):
    row = models.Credential(
        workspace_id=user["workspace_id"],
        name=body.name,
        kind=body.kind,
        username=body.username,
        secret_type=body.secret_type,
        secret_enc=encrypt_str(body.secret),
        passphrase_enc=encrypt_str(body.passphrase) if body.passphrase else None
    )
    db.add(row); db.commit(); db.refresh(row)
    return row