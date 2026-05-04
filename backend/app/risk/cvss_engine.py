"""
CVSS scoring utilities.
Maps CVSS base scores to severity labels per CVSS v3 specification.
"""


def severity_from_score(score: float | None) -> str:
    """
    Convert a numeric risk/CVSS score to a severity label.

    CVSS v3 thresholds:
      0.0        → none
      0.1 – 3.9  → low
      4.0 – 6.9  → medium
      7.0 – 8.9  → high
      9.0 – 10.0 → critical
    """
    if score is None:
        return "info"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score >= 0.1:
        return "low"
    return "info"


def cvss_baseline_from_severity(severity: str | None) -> float | None:
    """
    Derive a representative CVSS v3 base score from a severity label.

    Used as a fallback for plugin-discovered findings that don't map to a CVE
    (e.g. "Exposed debug console", "Missing HSTS header") so the UI doesn't
    show "—" for every non-CVE finding. Picks a midpoint of each band so the
    severity round-trip is lossless via severity_from_score().

      critical → 9.5  (band: 9.0–10.0)
      high     → 8.0  (band: 7.0–8.9)
      medium   → 5.5  (band: 4.0–6.9)
      low      → 2.5  (band: 0.1–3.9)
      info     → 0.0
    """
    if not severity:
        return None
    return {
        "critical": 9.5,
        "high":     8.0,
        "medium":   5.5,
        "low":      2.5,
        "info":     0.0,
    }.get(severity.lower())


def cvss_v3_vector_to_score(vector: str) -> float | None:
    """
    Very lightweight CVSS v3 base score approximation from a vector string.
    For full accuracy, use the `cvss` pip package.
    Returns None if the vector can't be parsed.
    """
    try:
        parts = dict(p.split(":") for p in vector.split("/") if ":" in p)
        # Attack Vector weight
        av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}.get(parts.get("AV", "N"), 0.85)
        # Attack Complexity
        ac = {"L": 0.77, "H": 0.44}.get(parts.get("AC", "L"), 0.77)
        # Privileges Required
        pr = {"N": 0.85, "L": 0.62, "H": 0.27}.get(parts.get("PR", "N"), 0.85)
        # User Interaction
        ui = {"N": 0.85, "R": 0.62}.get(parts.get("UI", "N"), 0.85)
        # Impact scores
        c = {"H": 0.56, "L": 0.22, "N": 0.0}.get(parts.get("C", "N"), 0.0)
        i = {"H": 0.56, "L": 0.22, "N": 0.0}.get(parts.get("I", "N"), 0.0)
        a = {"H": 0.56, "L": 0.22, "N": 0.0}.get(parts.get("A", "N"), 0.0)

        iss = 1 - (1 - c) * (1 - i) * (1 - a)
        if iss == 0:
            return 0.0
        impact = 6.42 * iss
        exploitability = 8.22 * av * ac * pr * ui
        base = min(impact + exploitability, 10.0)
        # Round up to 1 decimal
        import math
        return math.ceil(base * 10) / 10
    except Exception:
        return None
