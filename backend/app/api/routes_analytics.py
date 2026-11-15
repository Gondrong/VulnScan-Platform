"""
Analytics API routes – discovery, trending, diff, executive dashboard,
comparative reports, and re-verification scans.
"""
import ipaddress
import json
import logging
import socket
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from redis import Redis
from rq import Queue
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_role
from app.core.config import settings
from app.db import models
from app.worker_tasks import run_scan_job

logger = logging.getLogger("vulnscan.analytics")

router = APIRouter(prefix="/analytics", tags=["analytics"])

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def _redis() -> Redis:
    return Redis.from_url(settings.REDIS_URL)


# ─── 1. Auto Asset Discovery ────────────────────────────────────────────────


@router.post("/discover")
def discover_assets(
    body: dict,
    user=Depends(require_role("admin", "analyst")),
):
    """
    Lightweight asset discovery.

    Accepts either ``network_range`` (CIDR) or ``domain``.
    For domains: resolve DNS and return discovered IPs/subdomains.
    For CIDR: validate and return the range with IP count.
    """
    network_range = body.get("network_range")
    domain = body.get("domain")

    if not network_range and not domain:
        raise HTTPException(400, "Provide either 'network_range' (CIDR) or 'domain'")

    # --- CIDR discovery ---
    if network_range:
        try:
            net = ipaddress.ip_network(network_range, strict=False)
        except ValueError as exc:
            raise HTTPException(400, f"Invalid CIDR: {exc}")

        return {
            "type": "network",
            "network_range": str(net),
            "num_addresses": net.num_addresses,
            "first_ip": str(net.network_address),
            "last_ip": str(net.broadcast_address),
            "prefix_len": net.prefixlen,
        }

    # --- Domain discovery ---
    targets: list[dict] = []
    common_prefixes = [
        "", "www", "mail", "ftp", "api", "dev", "staging",
        "admin", "app", "portal", "vpn", "ns1", "ns2",
    ]

    for prefix in common_prefixes:
        hostname = f"{prefix}.{domain}" if prefix else domain
        try:
            ips = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            resolved = list({addr[4][0] for addr in ips})
            if resolved:
                targets.append({
                    "hostname": hostname,
                    "ips": resolved,
                    "type": "subdomain" if prefix else "apex",
                })
        except socket.gaierror:
            continue

    return {
        "type": "domain",
        "domain": domain,
        "discovered": targets,
        "count": len(targets),
    }


# ─── 2. Vulnerability Trending ──────────────────────────────────────────────


@router.get("/trending")
def vulnerability_trending(
    days: int = Query(30, ge=1, le=365),
    interval: str = Query("daily", regex="^(daily|weekly)$"),
    user=Depends(require_role("admin", "analyst", "viewer")),
    db: Session = Depends(get_db),
):
    """
    Time-series vulnerability data grouped by date.

    Returns counts per severity bucket and the mean time to remediate
    for closed findings within the requested window.
    """
    ws = user["ws"]
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    findings = (
        db.query(models.Finding)
        .filter(
            models.Finding.workspace_id == ws,
            models.Finding.opened_at >= cutoff,
        )
        .all()
    )

    # Build buckets
    buckets: dict[str, dict[str, int]] = defaultdict(
        lambda: {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    )

    for f in findings:
        if not f.opened_at:
            continue
        if interval == "weekly":
            # ISO week start (Monday)
            iso = f.opened_at.isocalendar()
            bucket_key = datetime.fromisocalendar(iso.year, iso.week, 1).strftime("%Y-%m-%d")
        else:
            bucket_key = f.opened_at.strftime("%Y-%m-%d")

        sev = (f.severity or "info").lower()
        if sev not in SEVERITY_ORDER:
            sev = "info"
        buckets[bucket_key]["total"] += 1
        buckets[bucket_key][sev] += 1

    series = [{"date": k, **v} for k, v in sorted(buckets.items())]

    # Mean time to remediate (closed findings in window)
    closed = (
        db.query(models.Finding)
        .filter(
            models.Finding.workspace_id == ws,
            models.Finding.opened_at >= cutoff,
            models.Finding.closed_at.isnot(None),
        )
        .all()
    )
    if closed:
        deltas = [
            (f.closed_at - f.opened_at).total_seconds() / 86400
            for f in closed
            if f.closed_at and f.opened_at
        ]
        mttr = round(sum(deltas) / len(deltas), 2) if deltas else None
    else:
        mttr = None

    return {
        "days": days,
        "interval": interval,
        "series": series,
        "mean_time_to_remediate_days": mttr,
    }


# ─── 3. Scan Diff / Delta Report ────────────────────────────────────────────


def _load_findings_for_job(db: Session, ws: int, job_id: int) -> list[models.Finding]:
    """Load all findings for a given scan job within the workspace."""
    job = (
        db.query(models.ScanJob)
        .filter(models.ScanJob.id == job_id, models.ScanJob.workspace_id == ws)
        .first()
    )
    if not job:
        raise HTTPException(404, f"Scan job {job_id} not found")
    return (
        db.query(models.Finding)
        .filter(models.Finding.job_id == job_id, models.Finding.workspace_id == ws)
        .all()
    )


def _finding_dict(f: models.Finding) -> dict:
    return {
        "id": f.id,
        "fingerprint": f.fingerprint,
        "title": f.title,
        "severity": f.severity,
        "plugin_id": f.plugin_id,
        "target": f.target,
        "risk_score": f.risk_score,
        "status": f.status,
    }


@router.get("/diff")
def scan_diff(
    job_a: int = Query(..., description="First scan job ID (before)"),
    job_b: int = Query(..., description="Second scan job ID (after)"),
    user=Depends(require_role("admin", "analyst", "viewer")),
    db: Session = Depends(get_db),
):
    """
    Compare findings between two scan jobs.

    Categories:
    - **new**: in job_b but not job_a
    - **fixed**: in job_a but not job_b
    - **unchanged**: same fingerprint and severity
    - **changed_severity**: same fingerprint but different severity
    """
    ws = user["ws"]
    findings_a = _load_findings_for_job(db, ws, job_a)
    findings_b = _load_findings_for_job(db, ws, job_b)

    map_a = {f.fingerprint: f for f in findings_a}
    map_b = {f.fingerprint: f for f in findings_b}

    fps_a = set(map_a.keys())
    fps_b = set(map_b.keys())

    new = [_finding_dict(map_b[fp]) for fp in (fps_b - fps_a)]
    fixed = [_finding_dict(map_a[fp]) for fp in (fps_a - fps_b)]

    unchanged = []
    changed_severity = []
    for fp in fps_a & fps_b:
        fa, fb = map_a[fp], map_b[fp]
        if (fa.severity or "").lower() == (fb.severity or "").lower():
            unchanged.append(_finding_dict(fb))
        else:
            changed_severity.append({
                "fingerprint": fp,
                "before": _finding_dict(fa),
                "after": _finding_dict(fb),
            })

    return {
        "job_a": job_a,
        "job_b": job_b,
        "new": new,
        "fixed": fixed,
        "unchanged": unchanged,
        "changed_severity": changed_severity,
    }


# ─── 4. Executive Dashboard ─────────────────────────────────────────────────


@router.get("/executive")
def executive_dashboard(
    user=Depends(require_role("admin", "analyst", "viewer")),
    db: Session = Depends(get_db),
):
    """
    All-in-one executive summary: risk posture, SLA compliance,
    top vulnerabilities, category breakdown, and scan activity.
    """
    ws = user["ws"]
    now_utc = datetime.now(timezone.utc)

    # ── Risk posture ──
    all_findings = (
        db.query(models.Finding)
        .filter(models.Finding.workspace_id == ws)
        .all()
    )
    sev_counts: dict[str, int] = {s: 0 for s in SEVERITY_ORDER}
    risk_scores: list[float] = []
    for f in all_findings:
        sev = (f.severity or "info").lower()
        sev_counts[sev] = sev_counts.get(sev, 0) + 1
        if f.risk_score is not None:
            risk_scores.append(f.risk_score)

    risk_posture = {
        "total_findings": len(all_findings),
        **sev_counts,
        "risk_score_avg": round(sum(risk_scores) / len(risk_scores), 2) if risk_scores else 0,
    }

    # ── SLA compliance ──
    sla = {"on_track": 0, "breached": 0, "approaching": 0}
    for f in all_findings:
        if f.status == "closed" or f.closed_at:
            continue
        if f.sla_days is None:
            continue
        days_open = (now_utc - f.opened_at).days if f.opened_at else 0
        remaining = f.sla_days - days_open
        if remaining < 0:
            sla["breached"] += 1
        elif remaining <= 3:
            sla["approaching"] += 1
        else:
            sla["on_track"] += 1

    # ── Top 10 vulns ──
    top_10 = sorted(all_findings, key=lambda x: x.risk_score or 0, reverse=True)[:10]
    top_10_vulns = [_finding_dict(f) for f in top_10]

    # ── Findings by category ──
    category_counts: dict[str, int] = defaultdict(int)
    for f in all_findings:
        prefix = (f.plugin_id or "unknown").split(".")[0]
        category_counts[prefix] += 1
    findings_by_category = dict(sorted(category_counts.items(), key=lambda x: x[1], reverse=True))

    # ── Scan activity ──
    jobs = (
        db.query(models.ScanJob)
        .filter(models.ScanJob.workspace_id == ws)
        .all()
    )
    completed = sum(1 for j in jobs if j.status == "done")
    failed = sum(1 for j in jobs if j.status == "failed")
    last_scan = max((j.created_at for j in jobs), default=None)

    scan_activity = {
        "total_scans": len(jobs),
        "completed": completed,
        "failed": failed,
        "last_scan_date": last_scan.isoformat() if last_scan else None,
    }

    return {
        "risk_posture": risk_posture,
        "sla_compliance": sla,
        "top_10_vulns": top_10_vulns,
        "findings_by_category": findings_by_category,
        "scan_activity": scan_activity,
    }


# ─── 5. Comparative Report ──────────────────────────────────────────────────


@router.get("/compare")
def comparative_report(
    job_a: int = Query(..., description="First scan job ID (before)"),
    job_b: int = Query(..., description="Second scan job ID (after)"),
    user=Depends(require_role("admin", "analyst", "viewer")),
    db: Session = Depends(get_db),
):
    """
    Higher-level comparison between two scan jobs with aggregate
    statistics and improvement percentage.
    """
    ws = user["ws"]
    findings_a = _load_findings_for_job(db, ws, job_a)
    findings_b = _load_findings_for_job(db, ws, job_b)

    def _stats(findings: list[models.Finding]) -> dict:
        counts = {s: 0 for s in SEVERITY_ORDER}
        scores: list[float] = []
        for f in findings:
            sev = (f.severity or "info").lower()
            counts[sev] = counts.get(sev, 0) + 1
            if f.risk_score is not None:
                scores.append(f.risk_score)
        return {
            "total": len(findings),
            **counts,
            "risk_score_avg": round(sum(scores) / len(scores), 2) if scores else 0,
        }

    stats_a = _stats(findings_a)
    stats_b = _stats(findings_b)

    # Improvement = reduction percentage in total findings
    if stats_a["total"] > 0:
        improvement_pct = round(
            ((stats_a["total"] - stats_b["total"]) / stats_a["total"]) * 100, 2
        )
    else:
        improvement_pct = 0.0

    # Severity comparison
    severity_comparison = {}
    for sev in SEVERITY_ORDER:
        severity_comparison[sev] = {
            "before": stats_a[sev],
            "after": stats_b[sev],
        }

    # Delta counts
    fps_a = {f.fingerprint for f in findings_a}
    fps_b = {f.fingerprint for f in findings_b}

    return {
        "summary": {
            "job_a_stats": stats_a,
            "job_b_stats": stats_b,
            "improvement_pct": improvement_pct,
        },
        "severity_comparison": severity_comparison,
        "new_findings_count": len(fps_b - fps_a),
        "fixed_findings_count": len(fps_a - fps_b),
    }


# ─── 6. Re-verification Scan ────────────────────────────────────────────────


@router.post("/reverify")
def reverify_scan(
    body: dict,
    user=Depends(require_role("admin", "analyst")),
    db: Session = Depends(get_db),
):
    """
    Create a new scan job that re-tests only the findings from a
    previous scan.  The new job's ``meta_json`` includes the original
    job ID and the fingerprints to re-verify.
    """
    job_id = body.get("job_id")
    if not job_id:
        raise HTTPException(400, "Missing 'job_id'")

    ws = user["ws"]
    original = (
        db.query(models.ScanJob)
        .filter(models.ScanJob.id == job_id, models.ScanJob.workspace_id == ws)
        .first()
    )
    if not original:
        raise HTTPException(404, f"Scan job {job_id} not found")

    # Gather fingerprints from original job findings
    findings = (
        db.query(models.Finding)
        .filter(models.Finding.job_id == job_id, models.Finding.workspace_id == ws)
        .all()
    )
    if not findings:
        raise HTTPException(400, f"No findings in scan job {job_id} to re-verify")

    fingerprints = list({f.fingerprint for f in findings if f.fingerprint})

    meta = {
        "reverify_job_id": job_id,
        "reverify_fingerprints": fingerprints,
    }

    new_job = models.ScanJob(
        workspace_id=ws,
        target=original.target,
        profile_id=original.profile_id,
        asset_id=original.asset_id,
        status="queued",
        scan_type=original.scan_type or "internal",
        meta_json=json.dumps(meta),
        created_by_user_id=user.get("uid"),
    )
    db.add(new_job)
    db.commit()
    db.refresh(new_job)

    try:
        q = Queue("scans", connection=_redis())
        rq_timeout = settings.SCAN_JOB_TIMEOUT
        q.enqueue(run_scan_job, new_job.id, job_timeout=rq_timeout)
        logger.info(
            "Reverify enqueued: job #%d (from #%d) target=%s fingerprints=%d",
            new_job.id, job_id, original.target, len(fingerprints),
        )
    except Exception as e:
        new_job.status = "failed"
        new_job.meta_json = json.dumps({
            **meta,
            "error": f"Failed to enqueue reverify scan: {e}",
        })
        db.commit()
        logger.error("Failed to enqueue reverify job #%d: %s", new_job.id, e)

    return {
        "id": new_job.id,
        "target": new_job.target,
        "status": new_job.status,
        "scan_type": new_job.scan_type,
        "reverify_job_id": job_id,
        "reverify_fingerprints_count": len(fingerprints),
        "created_at": new_job.created_at.isoformat() if new_job.created_at else None,
    }
