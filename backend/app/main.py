import hashlib
import logging

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db import models
from app.db.session import Base, SessionLocal, engine
from app.api.routes_auth import router as auth_router
from app.api.routes_credentials import router as cred_router
from app.api.routes_datasets import router as ds_router
from app.api.routes_scan import router as scan_router

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("vulnscan")

app = FastAPI(
    title="VulnScan Platform",
    version="1.0.0",
    description="Enterprise Risk-Based Vulnerability Management Platform",
)

# ─── CORS ─────────────────────────────────────────────────────────────────────
# Wide-open for dev; narrow via CORS_ORIGINS env in production
origins = settings.cors_origins_list()
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _hash(pw: str) -> str:
    return hashlib.sha256(pw.encode("utf-8")).hexdigest()


@app.on_event("startup")
def startup() -> None:
    # Create all tables
    Base.metadata.create_all(bind=engine)

    db: Session = SessionLocal()
    try:
        # Ensure default workspace exists
        ws = (
            db.query(models.Workspace)
            .filter(models.Workspace.name == settings.DEFAULT_WORKSPACE)
            .first()
        )
        if not ws:
            ws = models.Workspace(name=settings.DEFAULT_WORKSPACE)
            db.add(ws)
            db.commit()
            db.refresh(ws)

        # Ensure default admin exists
        admin = (
            db.query(models.User)
            .filter(models.User.email == settings.DEFAULT_ADMIN_EMAIL)
            .first()
        )
        if not admin:
            admin = models.User(
                workspace_id=ws.id,
                email=settings.DEFAULT_ADMIN_EMAIL,
                password_hash=_hash(settings.DEFAULT_ADMIN_PASSWORD),
                role="admin",
            )
            db.add(admin)
            db.commit()
            logger.info(
                "Created default admin: %s", settings.DEFAULT_ADMIN_EMAIL
            )
    finally:
        db.close()


@app.get("/healthz", tags=["health"])
def healthz():
    return {"ok": True, "version": "1.0.0"}


# ─── Audit middleware ──────────────────────────────────────────────────────────
@app.middleware("http")
async def audit_mw(request: Request, call_next):
    response = await call_next(request)
    try:
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            db: Session = SessionLocal()
            try:
                ip = request.client.host if request.client else ""
                ua = request.headers.get("User-Agent", "")
                db.add(
                    models.AuditLog(
                        workspace_id=0,
                        actor_email="",
                        action=f"{request.method} {request.url.path}",
                        resource="",
                        ip=ip,
                        user_agent=ua,
                    )
                )
                db.commit()
            finally:
                db.close()
    except Exception:
        pass
    return response


# ─── Routers ──────────────────────────────────────────────────────────────────
app.include_router(auth_router)
app.include_router(cred_router)
app.include_router(ds_router)
app.include_router(scan_router)
