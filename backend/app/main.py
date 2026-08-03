import logging
from datetime import datetime, timezone, timedelta

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
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
from app.api.routes_graph import router as graph_router
from app.api.routes_integrations import router as integrations_router
from app.api.routes_ai import router as ai_router
from app.api.routes_api_scanner import router as api_scanner_router
from app.api.routes_iac_scanner import router as iac_scanner_router
from app.api.routes_web_auth import router as web_auth_router
from app.api.routes_threat_intel import router as threat_intel_router
from app.api.routes_assets import router as assets_router
from app.api.routes_reports import router as reports_router
from app.api.routes_events import router as events_router
from app.api.routes_analytics import router as analytics_router

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("vulnscan")

app = FastAPI(
    title="VulnScan Platform",
    version=settings.PLATFORM_VERSION,
    description="Enterprise Risk-Based Vulnerability Management Platform",
)

# ─── CORS ──────────────────────────────────────────────────────────────────────
origins = settings.cors_origins_list()
if origins == ["*"]:
    logger.warning(
        "CORS_ORIGINS is set to '*' — all origins allowed. "
        "Set CORS_ORIGINS to specific origins in .env for production."
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origin_regex=r".*",
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
else:
    logger.info("CORS allowed origins: %s", origins)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Catch-all so unhandled errors still carry CORS headers."""
    logger.exception("Unhandled error on %s %s", request.method, request.url.path)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"},
    )


from app.core.password import hash_password as _hash


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
        # Add asset_id column to scan_jobs (nullable FK to assets) — runs after create_all so assets table exists
        """
        ALTER TABLE scan_jobs
            ADD COLUMN IF NOT EXISTS asset_id INTEGER REFERENCES assets(id) ON DELETE SET NULL;
        """,
        # Add user tracking columns
        """
        ALTER TABLE users
            ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ,
            ADD COLUMN IF NOT EXISTS last_login_at TIMESTAMPTZ,
            ADD COLUMN IF NOT EXISTS last_login_ip VARCHAR(45),
            ADD COLUMN IF NOT EXISTS last_login_location VARCHAR(100);
        """,
        # Track who launched each scan job
        """
        ALTER TABLE scan_jobs
            ADD COLUMN IF NOT EXISTS created_by_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL;
        """,
        # AI provider configs managed via UI (API keys stored encrypted)
        """
        CREATE TABLE IF NOT EXISTS ai_provider_configs (
            id SERIAL PRIMARY KEY,
            workspace_id INTEGER REFERENCES workspaces(id) ON DELETE CASCADE,
            provider_type VARCHAR(50) NOT NULL,
            name VARCHAR(100) NOT NULL,
            model VARCHAR(100) NOT NULL,
            api_key_enc TEXT,
            endpoint VARCHAR(500),
            extra_json TEXT DEFAULT '{}',
            enabled BOOLEAN DEFAULT TRUE,
            created_at TIMESTAMPTZ DEFAULT NOW()
        );
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

        # Add scan_schedules table migration
        try:
            db.execute(text("""
                CREATE TABLE IF NOT EXISTS scan_schedules (
                    id SERIAL PRIMARY KEY,
                    workspace_id INTEGER REFERENCES workspaces(id),
                    name VARCHAR(255) NOT NULL,
                    target VARCHAR(512) NOT NULL,
                    profile_id INTEGER REFERENCES profiles(id),
                    scan_type VARCHAR(20) DEFAULT 'internal',
                    schedule_type VARCHAR(20) DEFAULT 'interval',
                    interval_hours INTEGER DEFAULT 24,
                    custom_datetime TIMESTAMPTZ,
                    repeat BOOLEAN DEFAULT TRUE,
                    enabled BOOLEAN DEFAULT TRUE,
                    last_run_at TIMESTAMPTZ,
                    next_run_at TIMESTAMPTZ,
                    created_at TIMESTAMPTZ DEFAULT NOW()
                )
            """))
            db.commit()
            
            # Add integrations table migration
            db.execute(text("""
                CREATE TABLE IF NOT EXISTS integrations (
                    id SERIAL PRIMARY KEY,
                    workspace_id INTEGER REFERENCES workspaces(id),
                    provider VARCHAR(50) NOT NULL,
                    enabled BOOLEAN DEFAULT FALSE,
                    config_json TEXT DEFAULT '{}',
                    created_at TIMESTAMPTZ DEFAULT NOW()
                )
            """))
            db.commit()

            # Add AI analyses table
            db.execute(text("""
                CREATE TABLE IF NOT EXISTS ai_analyses (
                    id SERIAL PRIMARY KEY,
                    workspace_id INTEGER REFERENCES workspaces(id),
                    job_id INTEGER REFERENCES scan_jobs(id),
                    provider VARCHAR(50) NOT NULL,
                    mode VARCHAR(50) NOT NULL,
                    status VARCHAR(50) DEFAULT 'queued',
                    progress_json TEXT,
                    result_json TEXT,
                    error TEXT,
                    token_usage INTEGER,
                    duration_seconds FLOAT,
                    created_at TIMESTAMPTZ DEFAULT NOW(),
                    finished_at TIMESTAMPTZ
                )
            """))
            db.execute(text("CREATE INDEX IF NOT EXISTS ix_ai_analyses_job_id ON ai_analyses(job_id)"))
            db.execute(text("CREATE INDEX IF NOT EXISTS ix_ai_analyses_workspace_id ON ai_analyses(workspace_id)"))
            db.commit()

            # Add columns to existing table if missing
            for col, coltype in [
                ("schedule_type", "VARCHAR(20) DEFAULT 'interval'"),
                ("custom_datetime", "TIMESTAMPTZ"),
                ("repeat", "BOOLEAN DEFAULT TRUE"),
            ]:
                try:
                    db.execute(text(f"ALTER TABLE scan_schedules ADD COLUMN IF NOT EXISTS {col} {coltype}"))
                    db.commit()
                except Exception:
                    db.rollback()
        except Exception:
            db.rollback()

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
    return {"ok": True, "version": settings.PLATFORM_VERSION}


# ─── Schedule Runner (background) ─────────────────────────────────────────────
import asyncio as _asyncio
import threading as _threading

def _schedule_loop():
    """Background thread that checks for due scan schedules every 60s."""
    import time
    from redis import Redis
    from rq import Queue
    from app.worker_tasks import run_scan_job

    logger.info("Scheduler started")
    while True:
        time.sleep(60)
        try:
            db = SessionLocal()
            now_utc = datetime.now(timezone.utc)
            due = (
                db.query(models.ScanSchedule)
                .filter(
                    models.ScanSchedule.enabled == True,
                    models.ScanSchedule.next_run_at <= now_utc,
                )
                .all()
            )
            for sched in due:
                try:
                    job = models.ScanJob(
                        workspace_id=sched.workspace_id,
                        target=sched.target,
                        profile_id=sched.profile_id,
                        status="queued",
                        scan_type=sched.scan_type or "internal",
                    )
                    db.add(job)
                    db.commit()
                    db.refresh(job)

                    q = Queue("scans", connection=Redis.from_url(settings.REDIS_URL))
                    rq_timeout = settings.SCAN_BUDGET_SECONDS + 300
                    q.enqueue(run_scan_job, job.id, job_timeout=rq_timeout)

                    sched.last_run_at = now_utc

                    sched_type = getattr(sched, 'schedule_type', 'interval') or 'interval'
                    is_repeat = getattr(sched, 'repeat', True)

                    if sched_type == "custom" and not is_repeat:
                        # One-time custom schedule — disable after running
                        sched.enabled = False
                        sched.next_run_at = None
                    elif sched_type == "custom" and is_repeat:
                        # Repeating custom — use interval_hours for next run
                        sched.next_run_at = now_utc + timedelta(hours=sched.interval_hours)
                    else:
                        # Standard interval schedule
                        sched.next_run_at = now_utc + timedelta(hours=sched.interval_hours)

                    db.commit()
                    logger.info("Scheduled scan #%d for %s (schedule #%d)", job.id, sched.target, sched.id)
                except Exception as e:
                    logger.warning("Schedule #%d failed: %s", sched.id, e)
                    db.rollback()
            db.close()
        except Exception as e:
            logger.warning("Scheduler tick error: %s", e)

@app.on_event("startup")
def start_scheduler():
    t = _threading.Thread(target=_schedule_loop, daemon=True)
    t.start()


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
app.include_router(graph_router)
app.include_router(integrations_router)
app.include_router(ai_router)
app.include_router(api_scanner_router)
app.include_router(iac_scanner_router)
app.include_router(web_auth_router)
app.include_router(threat_intel_router)
app.include_router(assets_router)
app.include_router(reports_router)
app.include_router(events_router)
app.include_router(analytics_router)

