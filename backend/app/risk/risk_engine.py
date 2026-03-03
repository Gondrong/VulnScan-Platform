"""
Risk scoring engine.
Computes a composite risk score from CVSS, KEV status, asset criticality,
known exploits, and confidence.
"""

# When no CVSS score is available, use a base score that corresponds
# to the midpoint of each severity band in severity_from_score():
#   critical: 9.0-10.0 -> midpoint 9.5
#   high:     7.0-8.9  -> midpoint 8.0
#   medium:   4.0-6.9  -> midpoint 5.0
#   low:      0.1-3.9  -> midpoint 2.0
#   info:     0.0      -> 0.0
_SEVERITY_BASE_SCORE = {
    "critical": 9.5,
    "high": 8.0,
    "medium": 5.0,
    "low": 2.0,
    "info": 0.0,
}


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
        criticality: Asset criticality (1=low, 2=medium, 3=high, 4=critical)
        exploit_known: Whether a public exploit is known
        confidence: Scanner confidence in the finding (0-1)
        plugin_severity: The plugin's original severity label. When no CVSS
            is available, this determines the base score so that the final
            severity stays consistent with what the plugin intended.

    Returns:
        Float risk score between 0 and 10.
    """
    if cvss is not None:
        # CVSS is the authoritative score when available
        base = cvss
    elif plugin_severity and plugin_severity.lower() in _SEVERITY_BASE_SCORE:
        # No CVSS — use a base score that maps to the plugin's severity band
        base = _SEVERITY_BASE_SCORE[plugin_severity.lower()]
    else:
        # No CVSS and no plugin severity hint — assume medium
        base = 5.0

    # KEV multiplier
    if kev:
        base = min(base * 1.3, 10.0)
    elif exploit_known:
        base = min(base * 1.15, 10.0)

    # Asset criticality multiplier (1-4 scale maps to 0.8-1.2)
    crit_multiplier = {1: 0.8, 2: 1.0, 3: 1.1, 4: 1.2}.get(criticality, 1.0)
    base = min(base * crit_multiplier, 10.0)

    # Apply confidence
    base = base * max(min(confidence, 1.0), 0.1)

    return round(min(base, 10.0), 2)