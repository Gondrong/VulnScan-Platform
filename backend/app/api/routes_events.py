"""
Recent activity events — synthesized from scan jobs + findings.
Used by the dashboard's Live activity feed.
"""
from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_role
from app.db import models

router = APIRouter(prefix="/events", tags=["events"])


def _ago(dt: datetime) -> str:
    if not dt:
        return "—"
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    delta = datetime.now(timezone.utc) - dt
    s = int(delta.total_seconds())
    if s < 60:    return f"{max(s, 1)}s ago"
    if s < 3600:  return f"{s // 60}m ago"
    if s < 86400: return f"{s // 3600}h ago"
    return f"{s // 86400}d ago"


@router.get("/recent")
def recent_events(
    limit: int = 20,
    user=Depends(require_role("admin", "analyst", "viewer")),
    db: Session = Depends(get_db),
):
    """Return recent events: new findings + completed/failed/cancelled jobs."""
    ws = user["ws"]

    # Recent findings
    f_rows = (
        db.query(models.Finding)
        .filter(models.Finding.workspace_id == ws)
        .order_by(models.Finding.created_at.desc())
        .limit(limit)
        .all()
    )
    events = []
    for f in f_rows:
        events.append({
            "kind": "finding",
            "id": f.id,
            "sev": f.severity,
            "who": f.plugin_id or "scanner",
            "text": f.title,
            "target": f.target,
            "is_kev": f.is_kev,
            "at": f.created_at.isoformat() if f.created_at else None,
            "ago": _ago(f.created_at),
        })

    # Recent job state changes (done/failed/cancelled)
    j_rows = (
        db.query(models.ScanJob)
        .filter(models.ScanJob.workspace_id == ws)
        .order_by(models.ScanJob.id.desc())
        .limit(limit)
        .all()
    )
    for j in j_rows:
        if j.status not in ("done", "failed", "cancelled", "running"):
            continue
        ref_dt = j.finished_at or j.created_at
        text = {
            "done": f"Scan #{j.id} completed",
            "failed": f"Scan #{j.id} failed",
            "cancelled": f"Scan #{j.id} cancelled",
            "running": f"Scan #{j.id} dispatched",
        }.get(j.status, f"Scan #{j.id} updated")
        events.append({
            "kind": "job",
            "id": j.id,
            "sev": "critical" if j.status == "failed" else "info",
            "who": "scan-engine",
            "text": text,
            "target": j.target,
            "is_kev": False,
            "at": ref_dt.isoformat() if ref_dt else None,
            "ago": _ago(ref_dt),
        })

    # Sort by 'at' descending and trim
    events.sort(key=lambda e: e.get("at") or "", reverse=True)
    return {"events": events[:limit]}
