import hashlib
import logging

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db import models
from app.db.session import Base, SessionLocal, engine
from app.api.routes_auth import router as auth_router
from app.api.routes_credentials import router as cred_router
from app.api.routes_datasets import router as ds_router
from app.api.routes_scan import router as scan_router
from app.api.routes_settings import router as settings_router

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("vulnscan")

app = FastAPI(
    title="VulnScan Platform",
    version="1.0.0",
    description="Enterprise Risk-Based Vulnerability Management Platform",
)

# ─── CORS ──────────────────────────────────────────────────────────────────────
origins = settings.cors_origins_list()
if origins == ["*"]:
    app.add_middleware(
        CORSMiddleware,
        allow_origin_regex=r".*",
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
else:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )


def _hash(pw: str) -> str:
    return hashlib.sha256(pw.encode("utf-8")).hexdigest()


def _run_migrations(db: Session) -> None:
    migrations = [
        """
        ALTER TABLE scan_jobs
            ADD COLUMN IF NOT EXISTS scan_type VARCHAR(20) NOT NULL DEFAULT 'internal';
        """,
        # Make profile_id nullable so profiles can be deleted while keeping job history
        """
        ALTER TABLE scan_jobs
            ALTER COLUMN profile_id DROP NOT NULL;
        """,
        # Drop the strict FK constraint and re-add with ON DELETE SET NULL
        """
        DO $$
        BEGIN
            IF EXISTS (
                SELECT 1 FROM information_schema.table_constraints
                WHERE constraint_name = 'scan_jobs_profile_id_fkey'
                AND table_name = 'scan_jobs'
            ) THEN
                ALTER TABLE scan_jobs DROP CONSTRAINT scan_jobs_profile_id_fkey;
                ALTER TABLE scan_jobs ADD CONSTRAINT scan_jobs_profile_id_fkey
                    FOREIGN KEY (profile_id) REFERENCES profiles(id) ON DELETE SET NULL;
            END IF;
        END $$;
        """,
    ]
    for sql in migrations:
        try:
            db.execute(text(sql.strip()))
            db.commit()
        except Exception as exc:
            db.rollback()
            logger.warning("Migration skipped (%s): %.120s", type(exc).__name__, sql.strip())


@app.on_event("startup")
def startup() -> None:
    Base.metadata.create_all(bind=engine)

    db: Session = SessionLocal()
    try:
        _run_migrations(db)

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
            logger.info("Created default admin: %s", settings.DEFAULT_ADMIN_EMAIL)
    finally:
        db.close()


@app.get("/healthz", tags=["health"])
def healthz():
    return {"ok": True, "version": "1.0.0"}


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


# ─── Routers ────────────────────────────────────────────────────────────────────
app.include_router(auth_router)
app.include_router(cred_router)
app.include_router(ds_router)
app.include_router(scan_router)
app.include_router(settings_router)
