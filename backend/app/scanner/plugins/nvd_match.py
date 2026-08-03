from app.scanner.plugins.base import Plugin, PluginMeta, PluginResult, Finding
from app.db.session import SessionLocal
from app.db import models
from app.cve.dataset_loader import load_json
from app.cve.version_cmp import parse, is_likely_patched, extract_distro_patch
from app.scanner.context import stable_fingerprint

META = PluginMeta(
    plugin_id="cve.match.nvd_cpe",
    name="CVE Matching (NVD CPE)",
    category="cve",
    depends_on=["cpe.builder"],
    consumes=["cpe.candidates"],
    provides=["cve.nvd_hits"],
    enabled_by_default=True,
    timeout_seconds=6.0,
)

def split_cpe23(cpe: str):
    parts = (cpe or "").split(":")
    if len(parts) < 6: return None
    return {"part": parts[2], "vendor": parts[3], "product": parts[4], "version": parts[5] if len(parts) > 5 else "*"}

# Vendor aliases — NVD uses different vendor names for the same software.
# Maps alias → canonical name so both sides of a CPE comparison normalize.
_VENDOR_ALIASES = {
    "f5": "nginx",              # F5 acquired nginx; NVD uses both
    "pivotal_software": "vmware",  # VMware acquired Pivotal; Spring Boot
    "pivotal": "vmware",
    "oracle": "sun",            # Oracle acquired Sun; some old Java CVEs
    "sun": "oracle",
}

def _normalize_vendor(vendor: str) -> str:
    return _VENDOR_ALIASES.get(vendor, vendor)

def same_family(a: str, b: str) -> bool:
    aa=split_cpe23(a); bb=split_cpe23(b)
    if not (aa and bb): return False
    return (
        aa["part"] == bb["part"]
        and _normalize_vendor(aa["vendor"]) == _normalize_vendor(bb["vendor"])
        and aa["product"] == bb["product"]
    )

def range_ok(installed: str | None, m: dict) -> bool:
    vsi=m.get("versionStartIncluding"); vee=m.get("versionEndExcluding")
    vei=m.get("versionEndIncluding"); vse=m.get("versionStartExcluding")
    if not vsi and not vee and not vei and not vse:
        return True
    if not installed:
        return False
    v=parse(installed)
    if not v: return False
    if vsi:
        x=parse(vsi)
        if x and v < x: return False
    if vse:
        x=parse(vse)
        if x and v <= x: return False
    if vee:
        x=parse(vee)
        if x and v >= x: return False
    if vei:
        x=parse(vei)
        if x and v > x: return False
    return True

def _build_version_range_str(m: dict) -> str:
    """Build a human-readable version range string from NVD match data."""
    parts = []
    if m.get("versionStartIncluding"):
        parts.append(f">= {m['versionStartIncluding']}")
    if m.get("versionStartExcluding"):
        parts.append(f"> {m['versionStartExcluding']}")
    if m.get("versionEndIncluding"):
        parts.append(f"<= {m['versionEndIncluding']}")
    if m.get("versionEndExcluding"):
        parts.append(f"< {m['versionEndExcluding']}")
    return " and ".join(parts) if parts else "all versions"

def _build_remediation(cve: str, h: dict) -> str:
    """Build remediation text for a CVE finding."""
    parts = []

    # Parse affected component
    cpe_info = split_cpe23(h.get("matched_cpe", ""))
    if cpe_info:
        vendor = cpe_info["vendor"].replace("_", " ").title()
        product = cpe_info["product"].replace("_", " ").title()
        version = h.get("installed_version", "unknown")
        parts.append(
            f"[AFFECTED COMPONENT] {vendor} {product} version {version}"
        )

    # Add fix version if available from the match data
    vee = h.get("versionEndExcluding")
    vei = h.get("versionEndIncluding")
    if vee:
        parts.append(f"[FIX] Upgrade to version {vee} or later to resolve this vulnerability.")
    elif vei:
        parts.append(f"[FIX] Upgrade to a version newer than {vei} to resolve this vulnerability.")
    else:
        parts.append("[FIX] Upgrade to the latest patched version from the vendor.")

    # CVE reference
    if cve and cve.startswith("CVE-"):
        parts.append(
            f"[CVE DETAILS] Review {cve} at:\n"
            f"  - https://nvd.nist.gov/vuln/detail/{cve}\n"
            f"  - https://www.cve.org/CVERecord?id={cve}"
        )

    # Severity-based urgency
    severity = h.get("severity", "medium")
    if severity == "critical":
        parts.append("[URGENCY] CRITICAL — Patch immediately within 7 days. Consider temporary mitigations (disable affected feature, block at WAF, network segmentation).")
    elif severity == "high":
        parts.append("[URGENCY] HIGH — Patch within 14 days. Assess exposure and apply compensating controls if immediate patching is not feasible.")
    elif severity == "medium":
        parts.append("[URGENCY] MEDIUM — Plan patching within 30 days during next maintenance window.")

    return "\n\n".join(parts)


class Check(Plugin):
    async def run(self, target, ctx):
        ws_id = ctx.get("workspace_id")
        cands = ctx.get("cpe.candidates", []) or []
        if not cands:
            return PluginResult()

        # Distro-patch awareness: if we have OS info, we can detect backported fixes
        os_info = ctx.get("inventory.os", {}) or {}
        os_id = (os_info.get("os_id") or os_info.get("id") or os_info.get("distro") or "").lower()

        db = SessionLocal()
        hits=[]
        try:
            ds = db.query(models.CveDataset).filter(
                models.CveDataset.workspace_id==ws_id,
                models.CveDataset.kind=="nvd_cpe_cve",
                models.CveDataset.enabled==True
            ).all()
            for d in ds:
                data = load_json(d.path)
                for item in data or []:
                    for m in item.get("matches", []) or []:
                        cpe_db = m.get("cpe23")
                        if not cpe_db: continue
                        for c in cands:
                            if same_family(cpe_db, c.get("cpe23","")) and range_ok(c.get("version"), m):
                                hits.append({
                                    "cve": item.get("cve"),
                                    "summary": item.get("summary",""),
                                    "severity": item.get("severity","medium"),
                                    "cvss": item.get("cvss"),
                                    "refs": item.get("refs", []),
                                    "matched_cpe": c.get("cpe23"),
                                    "installed_version": c.get("version"),
                                    "confidence": c.get("confidence", 0.6),
                                    "versionEndExcluding": m.get("versionEndExcluding"),
                                    "versionEndIncluding": m.get("versionEndIncluding"),
                                    "version_range": _build_version_range_str(m),
                                })
                                break
        finally:
            db.close()

        findings=[]
        for h in hits[:3000]:
            cve = h.get("cve","CVE")
            fp = stable_fingerprint(target, META.plugin_id, cve, h.get("matched_cpe",""))
            installed = h.get("installed_version", "unknown")
            version_range = h.get("version_range", "all versions")

            # Build detailed description
            cpe_info = split_cpe23(h.get("matched_cpe", ""))
            product_name = cpe_info["product"].replace("_", " ").title() if cpe_info else "unknown"
            vendor_name = cpe_info["vendor"].replace("_", " ").title() if cpe_info else "unknown"

            # Check for distro-backported patches on banner/SSH-sourced CPEs
            cpe_source = h.get("source", "")
            raw_ver = h.get("raw_version", "")
            patched = (
                os_id
                and cpe_source in ("ssh", "banner")
                and raw_ver
                and is_likely_patched(raw_ver, os_id)
            )

            if patched:
                v_state = "likely_patched"
                v_method = "distro_backport_detected"
                v_confidence = 0.10
                v_note = (
                    f"The version string ({raw_ver}) contains a distro-specific patch suffix "
                    "indicating a backported security fix. The upstream version may appear "
                    "vulnerable, but the distro vendor has likely applied the relevant patches."
                )
            else:
                v_state = "provisional"
                v_method = "cpe_version_match_only"
                v_confidence = min(h.get("confidence", 0.6), 0.65)
                v_note = (
                    "Based on CPE version matching against NVD. "
                    "Verify the installed version is not patched by the OS vendor."
                )

            description = h.get("summary", "")
            if not description:
                description = f"{cve} affects {vendor_name} {product_name}"
            description += f"\n\nValidation state: {v_state}"
            description += f"\nValidation method: {v_method}"
            description += f"\n{v_note}"
            description += f"\n\nAffected component: {vendor_name} {product_name}"
            description += f"\nInstalled version: {installed}"
            description += f"\nVulnerable range: {version_range}"

            findings.append(Finding(
                severity=h.get("severity","medium"),
                plugin_id=META.plugin_id,
                title=f"Potential {cve}: {vendor_name} {product_name} {installed} (NVD match)",
                description=description,
                references=h.get("refs",[]),
                evidence=(
                    f"cpe={h.get('matched_cpe')} installed={installed} vulnerable_range={version_range} "
                    f"validation_state={v_state} validation_method={v_method}"
                ),
                affected=target,
                fingerprint=fp,
                cvss=h.get("cvss"),
                cve=cve,
                confidence=v_confidence,
                remediation=_build_remediation(cve, h),
            ))
        return PluginResult(findings=findings, artifacts={"cve.nvd_hits": hits})

