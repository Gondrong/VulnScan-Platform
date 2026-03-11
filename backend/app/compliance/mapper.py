"""
Compliance framework mapper.
Maps CVE IDs or plugin categories to compliance controls (PCI-DSS, ISO 27001, NIST, etc).
"""

from __future__ import annotations

# Friendly labels used when flattening structured framework maps.
_FRAMEWORK_LABELS: dict[str, str] = {
    "nist_800_53": "NIST SP 800-53",
    "pci_dss_v4": "PCI DSS v4",
    "cis_v8": "CIS Controls v8",
    "iso_27001": "ISO/IEC 27001",
}

# Lightweight built-in mappings; extend via CveDataset records of kind="compliance_map"
_BUILTIN: dict[str, list[str]] = {
    "cve": ["PCI-DSS 6.3", "NIST SP 800-53 SI-2", "ISO/IEC 27001 A.8.8"],
    "port_scan": ["PCI-DSS 1.1", "NIST SP 800-53 SC-7", "ISO/IEC 27001 A.8.20"],
    "fingerprint.http": ["OWASP A05:2021", "PCI-DSS 6.2", "ISO/IEC 27001 A.8.9"],
    "fingerprint.web.tech": ["OWASP A06:2021", "ISO/IEC 27001 A.8.8"],
}


def _framework_label(framework_key: str) -> str:
    return _FRAMEWORK_LABELS.get(framework_key, framework_key)


def _flatten_framework_map(frameworks: dict | None) -> set[str]:
    """Convert {framework: [controls]} into a flat set of strings."""
    results: set[str] = set()
    if not isinstance(frameworks, dict):
        return results

    for framework, controls in frameworks.items():
        if not isinstance(controls, list):
            continue
        label = _framework_label(str(framework))
        for control in controls:
            if control:
                results.add(f"{label} {control}")
    return results


def _plugin_matches(mapping: dict, plugin_id: str) -> bool:
    """Match by plugin_ids or plugin_category/category prefix."""
    plugin_ids = mapping.get("plugin_ids") or []
    if isinstance(plugin_ids, list):
        for pid in plugin_ids:
            if not isinstance(pid, str) or not pid:
                continue
            if plugin_id == pid or plugin_id.startswith(pid + "."):
                return True

    category = (mapping.get("plugin_category") or mapping.get("category") or "")
    if isinstance(category, str) and category:
        return plugin_id == category or plugin_id.startswith(category + ".")

    return False


def _extract_structured_controls(
    entry: dict,
    cve: str | None,
    plugin_id: str,
    severity: str | None,
) -> set[str]:
    """Handle modern compliance_map.json format with top-level 'mappings'."""
    results: set[str] = set()
    mappings = entry.get("mappings")
    if not isinstance(mappings, list):
        return results

    cve_upper = (cve or "").upper()
    sev_key = (severity or "").lower()

    for mapping in mappings:
        if not isinstance(mapping, dict):
            continue

        mapping_cve = str(mapping.get("cve") or "").upper()
        if mapping_cve and cve_upper and mapping_cve != cve_upper:
            continue
        if not _plugin_matches(mapping, plugin_id):
            continue

        # Generic framework controls for this mapping.
        results.update(_flatten_framework_map(mapping.get("frameworks")))

        # Severity-specific framework controls.
        severity_map = mapping.get("severity_map")
        if sev_key and isinstance(severity_map, dict):
            results.update(_flatten_framework_map(severity_map.get(sev_key)))

        # Optional direct controls list.
        controls = mapping.get("controls") or []
        if isinstance(controls, list):
            for control in controls:
                if control:
                    results.add(str(control))

    return results


def map_compliance_by_cve_or_category(
    cve: str | None,
    plugin_id: str,
    compliance_db: list[dict],
    severity: str | None = None,
) -> list[str]:
    """
    Return a list of compliance control strings relevant to a finding.

    Args:
        cve: Optional CVE identifier (e.g. "CVE-2021-44228")
        plugin_id: The scanner plugin that produced the finding
        compliance_db: List of dicts loaded from CveDataset records
        severity: Final normalized severity (critical/high/medium/low/info)
    """
    results: set[str] = set()

    for entry in compliance_db:
        if not isinstance(entry, dict):
            continue

        # Structured format (top-level "mappings").
        if "mappings" in entry:
            results.update(_extract_structured_controls(entry, cve, plugin_id, severity))
            continue

        # Legacy format: {cve|category, controls:[...]}
        entry_cve = str(entry.get("cve") or "")
        entry_cat = str(entry.get("category") or "")
        controls = entry.get("controls") or []

        matched = False
        if cve and entry_cve and cve.upper() == entry_cve.upper():
            matched = True
        if entry_cat and plugin_id.startswith(entry_cat):
            matched = True

        if matched and isinstance(controls, list):
            results.update(str(c) for c in controls if c)
            results.update(_flatten_framework_map(entry.get("frameworks")))

    # Built-in fallback mappings
    category = plugin_id.split(".")[0]
    if cve:
        results.update(_BUILTIN.get("cve", []))
    results.update(_BUILTIN.get(plugin_id, []))
    results.update(_BUILTIN.get(category, []))

    return sorted(results)
