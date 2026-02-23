def map_compliance_by_cve_or_category(cve: str | None, category: str | None, compliance_db: list[dict]) -> dict:
    out = {}
    for row in compliance_db or []:
        if cve and row.get("cve") == cve:
            out.update(row.get("mappings", {}))
        if category and row.get("category") == category:
            out.update(row.get("mappings", {}))
    return out
