"""
Risk scoring engine.
Computes a composite risk score from CVSS, KEV status, asset criticality,
known exploits, and confidence.
"""


def compute_risk(
    cvss: float | None,
    kev: bool = False,
    criticality: int = 2,
    exploit_known: bool = False,
    confidence: float = 1.0,
) -> float:
    """
    Compute a 0–10 composite risk score.

    Args:
        cvss: CVSS base score (0–10), or None if unknown
        kev: Whether the CVE is in CISA's Known Exploited Vulnerabilities catalog
        criticality: Asset criticality (1=low, 2=medium, 3=high, 4=critical)
        exploit_known: Whether a public exploit is known
        confidence: Scanner confidence in the finding (0–1)

    Returns:
        Float risk score between 0 and 10.
    """
    base = cvss if cvss is not None else 5.0  # default to medium if unknown

    # KEV multiplier — exploited in the wild is highest priority
    if kev:
        base = min(base * 1.3, 10.0)
    elif exploit_known:
        base = min(base * 1.15, 10.0)

    # Asset criticality multiplier (1–4 scale maps to 0.8–1.2)
    crit_multiplier = {1: 0.8, 2: 1.0, 3: 1.1, 4: 1.2}.get(criticality, 1.0)
    base = min(base * crit_multiplier, 10.0)

    # Apply confidence (low confidence = lower effective risk)
    base = base * max(min(confidence, 1.0), 0.1)

    return round(min(base, 10.0), 2)
