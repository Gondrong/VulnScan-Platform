from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.auth import create_token, require_auth
from app.core.config import settings
from app.core.geoip import resolve as geoip_resolve
from app.core.password import verify_password, needs_rehash, hash_password
from app.core.rate_limit import rate_limit
from app.db.session import get_db
from app.db import models

router = APIRouter(prefix="/auth", tags=["auth"])


class LoginRequest(BaseModel):
    email: str
    password: str


@router.post("/login")
def login(
    body: LoginRequest,
    request: Request,
    db: Session = Depends(get_db),
    _rl=Depends(rate_limit(max_requests=5, window_seconds=60)),
):
    user = (
        db.query(models.User)
        .filter(models.User.email == body.email)
        .first()
    )
    if not user or not verify_password(body.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    # Auto-migrate legacy SHA256 hashes to bcrypt on successful login
    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(body.password)
    user.last_login_at = datetime.now(timezone.utc)
    client_ip = request.headers.get("x-forwarded-for", "").split(",")[0].strip() or request.client.host
    user.last_login_ip = client_ip
    user.last_login_location = geoip_resolve(client_ip)
    db.commit()
    token = create_token({"sub": user.email, "uid": user.id, "role": user.role, "ws": user.workspace_id})
    return {"token": token, "role": user.role, "workspace_id": user.workspace_id}


@router.get("/me")
def me(claims=Depends(require_auth)):
    return claims
