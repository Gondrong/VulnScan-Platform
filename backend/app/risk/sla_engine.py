"""
SLA engine — assigns remediation deadlines based on finding severity.
Thresholds are based on common enterprise SLA policies.
"""

# SLA thresholds in days by severity
_SLA_DAYS: dict[str, int] = {
    "critical": 7,
    "high": 30,
    "medium": 90,
    "low": 180,
    "info": 365,
}


def assign_sla_days(severity: str) -> int:
    """
    Return the number of days to remediate a finding of the given severity.

    Args:
        severity: One of "critical", "high", "medium", "low", "info"

    Returns:
        Integer number of days.
    """
    return _SLA_DAYS.get(severity.lower(), 365)
