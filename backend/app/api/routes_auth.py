from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from app.db.session import SessionLocal
from app.db import models
from app.db.schemas import LoginIn, LoginOut
from app.core.auth import sign_jwt
import hashlib

router = APIRouter(prefix="/auth", tags=["auth"])

def _hash(pw: str) -> str:
    return hashlib.sha256(pw.encode("utf-8")).hexdigest()

@router.post("/login", response_model=LoginOut)
def login(body: LoginIn):
    db = SessionLocal()
    try:
        u = db.query(models.User).filter(models.User.email==body.email).first()
        if not u or u.password_hash != _hash(body.password):
            raise HTTPException(401, "invalid credentials")
        token = sign_jwt({"email": u.email, "workspace_id": u.workspace_id, "role": u.role, "user_id": u.id})
        return LoginOut(token=token)
    finally:
        db.close()