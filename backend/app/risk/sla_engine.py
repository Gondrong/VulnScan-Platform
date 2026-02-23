from datetime import datetime, timedelta, timezone

SLA_RULES = {"critical":7, "high":14, "medium":30, "low":60, "info":90}

def assign_sla_days(severity: str) -> int:
    return SLA_RULES.get(severity, 30)

def is_sla_breached(opened_at: datetime, sla_days: int, status: str) -> bool:
    if status == "closed":
        return False
    due = opened_at + timedelta(days=int(sla_days))
    return datetime.now(timezone.utc) > due

def mttr_days(opened_at: datetime, closed_at: datetime | None) -> float | None:
    if not closed_at:
        return None
    return round((closed_at - opened_at).total_seconds() / 86400, 2)
