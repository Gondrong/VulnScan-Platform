import logging
from datetime import datetime, timezone, timedelta

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool
from sqlalchemy import and_, or_, text
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.net import client_ip
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
        # Track when a worker actually starts an AI analysis, so the stale
        # watchdog can measure running time instead of time-since-created.
        """
        ALTER TABLE ai_analyses
            ADD COLUMN IF NOT EXISTS started_at TIMESTAMPTZ;
        """,
    ]
    for sql in migrations:
        try:
            # DDL needs ACCESS EXCLUSIVE, and a *queued* ACCESS EXCLUSIVE lock
            # blocks every later reader of the table — one long-running
            # transaction elsewhere is enough to freeze the whole application
            # behind a no-op "ADD COLUMN IF NOT EXISTS". Give up quickly
            # instead: these migrations are idempotent and retried next boot.
            db.execute(text("SET LOCAL lock_timeout = '3s'"))
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
        # Same reasoning as inside _run_migrations: never let idempotent DDL
        # queue for an exclusive lock, because a queued ACCESS EXCLUSIVE lock
        # blocks every subsequent reader of that table.
        try:
            db.execute(text("SET lock_timeout = '3s'"))
            db.commit()
        except Exception:
            db.rollback()

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
    import os
    import subprocess
    import time
    import json as _json
    from pathlib import Path
    from redis import Redis
    from rq import Queue
    from app.worker_tasks import run_scan_job

    logger.info("Scheduler started")

    # Counters for time-gated features
    _sla_check_counter = 0       # run every 60 ticks  (60 min)
    _backup_counter = 0          # run every 1440 ticks (24 hours)
    _update_check_counter = 0    # run every 1440 ticks (24 hours)

    while True:
        time.sleep(60)
        _sla_check_counter += 1
        _backup_counter += 1
        _update_check_counter += 1

        db = None
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
                    rq_timeout = settings.SCAN_JOB_TIMEOUT
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
            # ── Stale AI analysis detection ────────────────────────────
            # Fail an analysis only once it has genuinely overrun. Time is
            # measured from started_at (when a worker picked it up), because
            # an analysis sitting behind a busy queue has not consumed any of
            # its budget yet — measuring from created_at used to fail those
            # before they ever ran. Analyses that never start still get a
            # much longer grace period so a dead worker is eventually noticed.
            run_cutoff = now_utc - timedelta(seconds=settings.AI_STALE_AFTER_SECONDS)
            queue_cutoff = now_utc - timedelta(seconds=settings.AI_STALE_AFTER_SECONDS * 4)
            stale_analyses = (
                db.query(models.AiAnalysis)
                .filter(
                    models.AiAnalysis.status.in_(["queued", "running"]),
                    or_(
                        and_(
                            models.AiAnalysis.started_at.isnot(None),
                            models.AiAnalysis.started_at < run_cutoff,
                        ),
                        and_(
                            models.AiAnalysis.started_at.is_(None),
                            models.AiAnalysis.created_at < queue_cutoff,
                        ),
                    ),
                )
                .all()
            )
            for sa in stale_analyses:
                try:
                    if sa.started_at:
                        waited = int((now_utc - sa.started_at).total_seconds())
                        sa.error = (
                            f"Timed out — analysis ran for {waited}s without "
                            f"finishing (limit {settings.AI_STALE_AFTER_SECONDS}s)"
                        )
                    else:
                        waited = int((now_utc - sa.created_at).total_seconds())
                        sa.error = (
                            f"Timed out — never picked up by an AI worker after "
                            f"{waited}s. Check that the worker-ai container is running."
                        )
                    sa.status = "failed"
                    sa.finished_at = now_utc
                    db.commit()
                    # Restore job status if stuck in "analyzing"
                    stuck_job = db.query(models.ScanJob).filter(
                        models.ScanJob.id == sa.job_id,
                        models.ScanJob.status == "analyzing",
                    ).first()
                    if stuck_job:
                        stuck_job.status = "done"
                        db.commit()
                        logger.info("Stale AI #%d for job #%d: failed + job -> done", sa.id, sa.job_id)
                    else:
                        logger.info("Stale AI #%d for job #%d: failed", sa.id, sa.job_id)
                except Exception as e2:
                    logger.warning("Failed to clean stale AI #%d: %s", sa.id, e2)
                    db.rollback()

            # ── Feature 1: Auto Report Generation ─────────────────────────
            # Generate PDF reports for scan jobs that finished in the last 5 min
            # when the workspace has auto_report enabled.
            try:
                from app.api.routes_settings import _get_setting
                five_min_ago = now_utc - timedelta(minutes=5)
                recent_done_jobs = (
                    db.query(models.ScanJob)
                    .filter(
                        models.ScanJob.status == "done",
                        models.ScanJob.finished_at >= five_min_ago,
                        models.ScanJob.finished_at <= now_utc,
                    )
                    .all()
                )
                for rj in recent_done_jobs:
                    try:
                        auto_cfg = _get_setting(
                            db, rj.workspace_id, "auto_report",
                            {"enabled": False, "format": "pdf"},
                        )
                        if not auto_cfg.get("enabled"):
                            continue
                        report_dir = Path("/data/reports")
                        report_dir.mkdir(parents=True, exist_ok=True)
                        report_path = report_dir / f"vulnscan-auto-{rj.id}.pdf"
                        if report_path.exists():
                            continue
                        # Gather findings for this job
                        findings = (
                            db.query(models.Finding)
                            .filter(models.Finding.job_id == rj.id)
                            .all()
                        )
                        # Use default template
                        template = {
                            "name": "Auto-generated",
                            "sections": ["summary", "severity", "findings", "remediation"],
                        }
                        from app.api.routes_reports import _as_pdf
                        pdf_bytes = _as_pdf(rj, findings, template)
                        report_path.write_bytes(pdf_bytes)
                        logger.info(
                            "Auto-report generated for job #%d → %s (%d bytes)",
                            rj.id, report_path, len(pdf_bytes),
                        )
                    except Exception as e_rpt:
                        logger.warning("Auto-report for job #%d failed: %s", rj.id, e_rpt)
            except Exception as e_feat1:
                logger.warning("Auto-report feature error: %s", e_feat1)

            # ── Feature 2: SLA Breach Alert ───────────────────────────────
            # Check periodically for open findings that have exceeded their
            # SLA deadline.  Configurable per-workspace via /settings/sla-alert.
            # Default: disabled. Enable in Settings → SLA Alert.
            try:
                if _sla_check_counter >= 60:
                    _sla_check_counter = 0

                    # Get workspaces that have SLA alerts enabled
                    enabled_ws_ids = []
                    for ws_obj in db.query(models.Workspace).all():
                        sla_cfg = _get_setting(
                            db, ws_obj.id, "sla_breach_alert",
                            {"enabled": False},
                        )
                        if sla_cfg.get("enabled"):
                            enabled_ws_ids.append(ws_obj.id)

                    if enabled_ws_ids:
                        open_findings = (
                            db.query(models.Finding)
                            .filter(
                                models.Finding.status == "open",
                                models.Finding.sla_days.isnot(None),
                                models.Finding.workspace_id.in_(enabled_ws_ids),
                            )
                            .all()
                        )
                        if open_findings:
                            r = Redis.from_url(settings.REDIS_URL)
                            from app.scanner.notifier import (
                                send_slack_notification,
                                send_teams_notification,
                                send_email_notification,
                                send_webhook_notification,
                            )
                            for f in open_findings:
                                try:
                                    days_open = (now_utc - f.opened_at).days if f.opened_at else 0
                                    if days_open <= f.sla_days:
                                        continue
                                    redis_key = f"sla_alert:{f.id}"
                                    if r.exists(redis_key):
                                        continue
                                    r.setex(redis_key, 86400, "1")
                                    msg_text = (
                                        f"SLA BREACH: Finding #{f.id} \"{f.title}\" "
                                        f"(severity={f.severity}) has been open for "
                                        f"{days_open} days (SLA limit: {f.sla_days} days)"
                                    )
                                    integrations = (
                                        db.query(models.Integration)
                                        .filter(
                                            models.Integration.workspace_id == f.workspace_id,
                                            models.Integration.enabled == True,
                                        )
                                        .all()
                                    )
                                    for integ in integrations:
                                        try:
                                            cfg = _json.loads(integ.config_json or "{}")
                                            if integ.provider == "slack":
                                                send_slack_notification(cfg, msg_text)
                                            elif integ.provider == "teams":
                                                send_teams_notification(cfg, {"title": "SLA Breach", "text": msg_text})
                                            elif integ.provider == "email":
                                                send_email_notification(cfg, f"VulnScan SLA Breach — Finding #{f.id}", msg_text)
                                            elif integ.provider == "webhook":
                                                send_webhook_notification(cfg, {
                                                    "event": "sla_breach", "finding_id": f.id,
                                                    "title": f.title, "severity": f.severity,
                                                    "days_open": days_open, "sla_days": f.sla_days,
                                                })
                                        except Exception as e_integ:
                                            logger.warning("SLA alert (%s) finding #%d: %s", integ.provider, f.id, e_integ)
                                    logger.info(
                                        "SLA breach alert sent for finding #%d (%d days > %d SLA)",
                                        f.id, days_open, f.sla_days,
                                    )
                                except Exception as e_f:
                                    logger.warning("SLA check for finding #%d failed: %s", f.id, e_f)
            except Exception as e_feat2:
                logger.warning("SLA breach alert feature error: %s", e_feat2)

            # ── Feature 3: Database Backup ────────────────────────────────
            # Run pg_dump every 1440 ticks (≈24 hours), keep last 7 backups.
            try:
                if _backup_counter >= 1440:
                    _backup_counter = 0
                    backup_dir = Path("/data/backups")
                    backup_dir.mkdir(parents=True, exist_ok=True)
                    date_str = now_utc.strftime("%Y%m%d-%H%M%S")
                    backup_file = backup_dir / f"vulnscan-{date_str}.sql.gz"

                    # Parse DATABASE_URL for pg_dump connection params
                    db_url = settings.DATABASE_URL
                    env = os.environ.copy()
                    # DATABASE_URL format: postgresql://user:pass@host:port/dbname
                    import re as _re
                    m = _re.match(
                        r"postgresql(?:\+\w+)?://([^:]+):([^@]+)@([^:/]+)(?::(\d+))?/(.+)",
                        db_url,
                    )
                    if m:
                        pg_user, pg_pass, pg_host, pg_port, pg_db = m.groups()
                        pg_port = pg_port or "5432"
                        env["PGPASSWORD"] = pg_pass
                        cmd = (
                            f"pg_dump -h {pg_host} -p {pg_port} -U {pg_user} -d {pg_db} "
                            f"| gzip > {backup_file}"
                        )
                    else:
                        # Fallback to default container names
                        env["PGPASSWORD"] = "app"
                        cmd = f"pg_dump -h db -U app -d app | gzip > {backup_file}"

                    result = subprocess.run(
                        cmd, shell=True, env=env,
                        capture_output=True, text=True, timeout=600,
                    )
                    if result.returncode == 0:
                        logger.info("Database backup created: %s", backup_file)
                    else:
                        logger.warning(
                            "Database backup failed (rc=%d): %s",
                            result.returncode, result.stderr[:500],
                        )

                    # Rotate: keep only the last 7 backups
                    existing = sorted(backup_dir.glob("vulnscan-*.sql.gz"))
                    if len(existing) > 7:
                        for old in existing[:-7]:
                            try:
                                old.unlink()
                                logger.info("Deleted old backup: %s", old.name)
                            except Exception as e_del:
                                logger.warning("Failed to delete old backup %s: %s", old.name, e_del)
            except Exception as e_feat3:
                logger.warning("Database backup feature error: %s", e_feat3)

            # ── Feature 4: Auto Update Check ─────────────────────────────
            # Check GitHub for new releases every 1440 ticks (≈24 hours).
            # If update available, send notification via configured integrations.
            try:
                if _update_check_counter >= 1440:
                    _update_check_counter = 0
                    import urllib.request
                    current = settings.PLATFORM_VERSION
                    repo = settings.GITHUB_REPO
                    try:
                        url = f"https://api.github.com/repos/{repo}/releases/latest"
                        req = urllib.request.Request(url, headers={
                            "Accept": "application/vnd.github+json",
                            "User-Agent": "VulnScan-Platform",
                        })
                        with urllib.request.urlopen(req, timeout=15) as resp:
                            release = _json.loads(resp.read().decode())

                        latest_tag = release.get("tag_name", "")
                        latest_ver = latest_tag.lstrip("vV")

                        def _vt(v):
                            try: return tuple(int(x) for x in v.split("."))
                            except: return (0, 0, 0)

                        if _vt(latest_ver) > _vt(current):
                            # Clear cached check so UI also picks it up
                            try:
                                r_upd = Redis.from_url(settings.REDIS_URL)
                                r_upd.delete("update_check_cache")
                            except Exception:
                                pass

                            msg = (
                                f"VulnScan update available: v{current} → v{latest_ver}\n"
                                f"Release: {release.get('name', latest_tag)}\n"
                                f"Update from Settings → System or run: git pull && docker compose up -d --build"
                            )
                            logger.info("Update available: v%s → v%s", current, latest_ver)

                            # Notify via all enabled integrations (all workspaces)
                            from app.scanner.notifier import (
                                send_slack_notification,
                                send_teams_notification,
                                send_email_notification,
                                send_webhook_notification,
                            )
                            all_integrations = (
                                db.query(models.Integration)
                                .filter(models.Integration.enabled == True)
                                .all()
                            )
                            for integ in all_integrations:
                                try:
                                    cfg = _json.loads(integ.config_json or "{}")
                                    if integ.provider == "slack":
                                        send_slack_notification(cfg, msg)
                                    elif integ.provider == "teams":
                                        send_teams_notification(cfg, {"title": "VulnScan Update Available", "text": msg})
                                    elif integ.provider == "email":
                                        send_email_notification(cfg, "VulnScan Update Available", msg)
                                    elif integ.provider == "webhook":
                                        send_webhook_notification(cfg, {
                                            "event": "update_available",
                                            "current": current,
                                            "latest": latest_ver,
                                        })
                                except Exception:
                                    pass
                        else:
                            logger.debug("Update check: v%s is latest", current)
                    except Exception as e_gh:
                        logger.debug("Update check failed: %s", e_gh)
            except Exception as e_feat4:
                logger.warning("Update check feature error: %s", e_feat4)

        except Exception as e:
            logger.warning("Scheduler tick error: %s", e)
        finally:
            # Always return the connection to the pool — a tick that raises
            # before this point would otherwise leak one session per minute
            # and exhaust the SQLAlchemy pool.
            if db is not None:
                try:
                    db.close()
                except Exception as e_close:
                    logger.warning("Scheduler session close failed: %s", e_close)

@app.on_event("startup")
def start_scheduler():
    t = _threading.Thread(target=_schedule_loop, daemon=True)
    t.start()


def _write_audit(method: str, path: str, ip: str, ua: str) -> None:
    """Blocking audit write — must run off the event loop."""
    db: Session = SessionLocal()
    try:
        db.add(
            models.AuditLog(
                workspace_id=0,
                actor_email="",
                action=f"{method} {path}",
                resource="",
                ip=ip,
                user_agent=ua,
            )
        )
        db.commit()
    except Exception as exc:
        db.rollback()
        logger.warning("Audit log write failed: %s", exc)
    finally:
        db.close()


@app.middleware("http")
async def audit_mw(request: Request, call_next):
    response = await call_next(request)
    try:
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            # Run in a worker thread: a synchronous commit here blocks the
            # whole event loop, and it also holds a pool connection on the
            # critical path of every mutating request.
            ip = client_ip(request)
            ua = request.headers.get("User-Agent", "")
            await run_in_threadpool(
                _write_audit, request.method, request.url.path, ip, ua,
            )
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

