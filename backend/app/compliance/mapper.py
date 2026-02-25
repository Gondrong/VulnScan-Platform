"""
Compliance framework mapper.
Maps CVE IDs or plugin categories to compliance controls (PCI-DSS, ISO27001, NIST, etc).
"""

# Lightweight built-in mappings; extend via CveDataset records of kind="compliance_map"
_BUILTIN: dict[str, list[str]] = {
    "cve": ["PCI-DSS 6.3", "NIST SP 800-53 SI-2"],
    "port_scan": ["PCI-DSS 1.1", "NIST SP 800-53 SC-7"],
    "fingerprint.http": ["OWASP A05:2021", "PCI-DSS 6.2"],
    "fingerprint.web.tech": ["OWASP A06:2021"],
}


def map_compliance_by_cve_or_category(
    cve: str | None,
    plugin_id: str,
    compliance_db: list[dict],
) -> list[str]:
    """
    Return a list of compliance control strings relevant to a finding.

    Args:
        cve: Optional CVE identifier (e.g. "CVE-2021-44228")
        plugin_id: The scanner plugin that produced the finding
        compliance_db: List of dicts loaded from CveDataset records
    """
    results: set[str] = set()

    # Check external compliance_db (user-provided datasets)
    for entry in compliance_db:
        entry_cve = entry.get("cve") or ""
        entry_cat = entry.get("category") or ""
        controls = entry.get("controls") or []

        if cve and entry_cve and cve.upper() == entry_cve.upper():
            results.update(controls)
        if entry_cat and plugin_id.startswith(entry_cat):
            results.update(controls)

    # Fall back to built-in mappings
    category = plugin_id.split(".")[0]
    if cve:
        results.update(_BUILTIN.get("cve", []))
    results.update(_BUILTIN.get(plugin_id, []))
    results.update(_BUILTIN.get(category, []))

    return sorted(results)
