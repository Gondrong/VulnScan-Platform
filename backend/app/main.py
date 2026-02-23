from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
import hashlib

from app.core.config import settings
from app.db.session import engine, SessionLocal, Base
from app.db import models
from app.api.routes_auth import router as auth_router
from app.api.routes_credentials import router as cred_router
from app.api.routes_datasets import router as ds_router
from app.api.routes_scan import router as scan_router

app = FastAPI(title="VulnScan Platform", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_credentials=True,
    allow_methods=["*"], allow_headers=["*"]
)

def _hash(pw: str) -> str:
    return hashlib.sha256(pw.encode("utf-8")).hexdigest()

@app.on_event("startup")
def startup():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        ws = db.query(models.Workspace).filter(models.Workspace.name==settings.DEFAULT_WORKSPACE).first()
        if not ws:
            ws = models.Workspace(name=settings.DEFAULT_WORKSPACE)
            db.add(ws); db.commit(); db.refresh(ws)

        admin = db.query(models.User).filter(models.User.email==settings.DEFAULT_ADMIN_EMAIL).first()
        if not admin:
            admin = models.User(
                workspace_id=ws.id,
                email=settings.DEFAULT_ADMIN_EMAIL,
                password_hash=_hash(settings.DEFAULT_ADMIN_PASSWORD),
                role="admin"
            )
            db.add(admin); db.commit()
    finally:
        db.close()

@app.get("/healthz")
def healthz():
    return {"ok": True}

# simple audit logging for mutating requests
@app.middleware("http")
async def audit_mw(request: Request, call_next):
    resp = await call_next(request)
    try:
        if request.method in ("POST","PUT","PATCH","DELETE"):
            db = SessionLocal()
            try:
                ip = request.client.host if request.client else ""
                ua = request.headers.get("User-Agent","")
                # workspace_id unknown without token - keep generic
                db.add(models.AuditLog(workspace_id=0, actor_email="", action=f"{request.method} {request.url.path}", resource="", ip=ip, user_agent=ua))
                db.commit()
            finally:
                db.close()
    except:
        pass
    return resp

app.include_router(auth_router)
app.include_router(cred_router)
app.include_router(ds_router)
app.include_router(scan_router)
