def compute_risk(cvss: float | None, kev: bool, criticality: int, exploit_known: bool, confidence: float) -> float:
    base = float(cvss) if cvss is not None else 5.0
    if exploit_known:
        base *= 1.2
    if kev:
        base += 2.0
    base += {1:0.0, 2:1.0, 3:2.0}.get(int(criticality or 2), 1.0)
    base *= float(confidence or 1.0)
    if base > 10.0:
        base = 10.0
    if base < 0.0:
        base = 0.0
    return round(base, 2)
