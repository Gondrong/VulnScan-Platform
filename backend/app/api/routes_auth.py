import hashlib
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.auth import create_token, require_auth
from app.core.config import settings
from app.core.geoip import resolve as geoip_resolve
from app.db.session import get_db
from app.db import models

router = APIRouter(prefix="/auth", tags=["auth"])


def _hash(pw: str) -> str:
    return hashlib.sha256(pw.encode("utf-8")).hexdigest()


class LoginRequest(BaseModel):
    email: str
    password: str


@router.post("/login")
def login(body: LoginRequest, request: Request, db: Session = Depends(get_db)):
    user = (
        db.query(models.User)
        .filter(models.User.email == body.email)
        .first()
    )
    if not user or user.password_hash != _hash(body.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    user.last_login_at = datetime.now(timezone.utc)
    client_ip = request.headers.get("x-forwarded-for", "").split(",")[0].strip() or request.client.host
    user.last_login_ip = client_ip
    user.last_login_location = geoip_resolve(client_ip)
    db.commit()
    token = create_token({"sub": user.email, "role": user.role, "ws": user.workspace_id})
    return {"token": token, "role": user.role, "workspace_id": user.workspace_id}


@router.get("/me")
def me(claims=Depends(require_auth)):
    return claims
