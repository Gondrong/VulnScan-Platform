from fastapi import Depends, Request, HTTPException
from sqlalchemy.orm import Session
from app.db.session import SessionLocal
from app.core.auth import get_bearer_token, verify_jwt

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_current_user(req: Request):
    token = get_bearer_token(req)
    payload = verify_jwt(token)
    return payload  # {email, workspace_id, role, user_id}

def require_role(*roles):
    def dep(user=Depends(get_current_user)):
        if user.get("role") not in roles:
            raise HTTPException(403, "forbidden")
        return user
    return dep