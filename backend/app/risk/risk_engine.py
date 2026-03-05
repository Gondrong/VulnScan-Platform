"""
Risk scoring engine.
Computes a composite risk score from CVSS, KEV status, asset criticality,
known exploits, and confidence.
"""

# When no CVSS, use a base score at the midpoint of each severity band
_SEVERITY_BASE_SCORE = {
    "critical": 9.5,
    "high": 8.0,
    "medium": 5.0,
    "low": 2.0,
    "info": 0.0,
}

# Severity band floor thresholds (matching cvss_engine.severity_from_score)
_SEVERITY_FLOOR = {
    "critical": 9.0,
    "high": 7.0,
    "medium": 4.0,
    "low": 0.1,
    "info": 0.0,
}


def _cvss_severity(score: float) -> str:
    """Map a score to its severity label."""
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score >= 0.1:
        return "low"
    return "info"


def compute_risk(
    cvss: float | None,
    kev: bool = False,
    criticality: int = 2,
    exploit_known: bool = False,
    confidence: float = 1.0,
    plugin_severity: str = "",
) -> float:
    """
    Compute a 0-10 composite risk score.

    Args:
        cvss: CVSS base score (0-10), or None if unknown
        kev: Whether the CVE is in CISA KEV catalog
        criticality: Asset criticality (1=low, 2=normal, 3=high, 4=critical, 5=maximum)
        exploit_known: Whether a public exploit is known
        confidence: Scanner confidence in the finding (0-1)
        plugin_severity: The plugin's original severity label. Used as
            fallback base score when no CVSS is available.

    Returns:
        Float risk score between 0 and 10.
    """
    if cvss is not None:
        base = cvss
    elif plugin_severity and plugin_severity.lower() in _SEVERITY_BASE_SCORE:
        base = _SEVERITY_BASE_SCORE[plugin_severity.lower()]
    else:
        base = 5.0

    # Remember the CVSS-derived severity before adjustments
    original_severity = _cvss_severity(base) if cvss is not None else None

    # KEV multiplier
    if kev:
        base = min(base * 1.3, 10.0)
    elif exploit_known:
        base = min(base * 1.15, 10.0)

    # Asset criticality multiplier (1-5 -> 0.8-1.3)
    crit_multiplier = {1: 0.8, 2: 1.0, 3: 1.1, 4: 1.2, 5: 1.3}.get(criticality, 1.0)
    base = min(base * crit_multiplier, 10.0)

    # Apply confidence
    base = base * max(min(confidence, 1.0), 0.1)

    # Severity floor guard: when CVSS is authoritative and confidence is
    # reasonably high (>=0.8), don't let the score drop below the CVSS
    # severity band floor. A CVSS 9.8 critical should stay critical even
    # with confidence 0.9 (which would otherwise give 8.82 = high).
    if original_severity and confidence >= 0.8:
        floor = _SEVERITY_FLOOR.get(original_severity, 0.0)
        if base < floor:
            base = floor

    return round(min(base, 10.0), 2)