import hashlib
from datetime import datetime, timezone

import bcrypt
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
    """Hash password using bcrypt with automatic salt generation.
    
    bcrypt provides:
    - Automatic salt generation
    - Configurable cost factor (2^12 iterations by default)
    - Resistance to GPU/ASIC attacks
    - Timing-attack safe
    """
    return bcrypt.hashpw(pw.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")


def _verify(pw: str, hashed: str) -> bool:
    """Verify password against bcrypt hash.
    
    Args:
        pw: Plain text password
        hashed: Bcrypt hash from database
        
    Returns:
        True if password matches, False otherwise
    """
    return bcrypt.checkpw(pw.encode("utf-8"), hashed.encode("utf-8"))


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
    if not user or not _verify(body.password, user.password_hash):
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
