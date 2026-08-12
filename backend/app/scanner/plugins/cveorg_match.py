"""
CVE.org Affected-Product Matcher — fallback CVE detection for entries
where NVD has not yet published CPE match criteria.

Uses the 'affected' field from CVE.org CNA data (vendor, product, version
ranges) to match against detected software. This catches new CVEs within
hours of publication, rather than waiting days/weeks for NVD CPE data.

Runs AFTER nvd_match so it only reports CVEs not already found.
"""
import json
import logging
import os

from app.scanner.plugins.base import Plugin, PluginMeta, PluginResult, Finding
from app.scanner.context import stable_fingerprint
from app.cve.version_cmp import parse as parse_version
from app.db.session import SessionLocal
from app.db import models
from app.cve.dataset_loader import load_json

logger = logging.getLogger("vulnscan.cveorg_match")

META = PluginMeta(
    plugin_id="cve.match.cveorg",
    name="CVE Matching (CVE.org Affected)",
    category="cve",
    depends_on=["cpe.builder"],
    soft_depends_on=["cve.match.nvd_cpe"],
    consumes=["cpe.candidates", "cve.nvd_hits"],
    provides=["cve.cveorg_hits"],
    enabled_by_default=True,
    timeout_seconds=6.0,
)

# Normalize vendor/product names for fuzzy matching
_VENDOR_ALIASES = {
    "f5": "nginx",
    "f5, inc.": "nginx",
    "f5 networks": "nginx",
    "pivotal software": "vmware",
    "pivotal": "vmware",
    "spring": "vmware",
    "oracle": "oracle",
    "sun microsystems": "oracle",
    "the apache software foundation": "apache",
    "apache software foundation": "apache",
    "php group": "php",
    "the php group": "php",
    "nodejs": "node.js",
    "node.js foundation": "nodejs",
    "openjs foundation": "nodejs",
    "drupal.org": "drupal",
    "wordpress.org": "wordpress",
    "wordpress foundation": "wordpress",
    "automattic": "wordpress",
    "joomla!": "joomla",
    "joomla! project": "joomla",
}

_PRODUCT_ALIASES = {
    "http server": "http_server",
    "http_server": "http_server",
    "httpd": "http_server",
    "spring framework": "spring_framework",
    "spring boot": "spring_boot",
    "node.js": "node.js",
    "wordpress": "wordpress",
    "joomla!": "joomla",
}


def _norm(s: str) -> str:
    """Normalize vendor/product string for comparison."""
    s = s.strip().lower()
    s = s.replace("_", " ").replace("-", " ")
    return _VENDOR_ALIASES.get(s, _PRODUCT_ALIASES.get(s, s))


def _version_in_range(installed_ver: str, affected: dict) -> bool:
    """Check if installed version falls within the affected range."""
    v = parse_version(installed_ver)
    if not v:
        return False

    less_than = affected.get("lessThan")
    less_than_or_eq = affected.get("lessThanOrEqual")
    ver_start = affected.get("versionStart")

    # Check lower bound
    if ver_start:
        start = parse_version(ver_start)
        if start and v < start:
            return False

    # Check upper bound
    if less_than:
        upper = parse_version(less_than)
        if upper and v >= upper:
            return False
    elif less_than_or_eq:
        upper = parse_version(less_than_or_eq)
        if upper and v > upper:
            return False
    else:
        # No upper bound specified — can't determine range
        return False

    return True


class Check(Plugin):
    async def run(self, target, ctx):
        ws_id = ctx.get("workspace_id")
        cands = ctx.get("cpe.candidates", []) or []
        if not cands:
            return PluginResult()

        # Get CVE IDs already found by nvd_match to avoid duplicates
        nvd_hits = ctx.get("cve.nvd_hits", []) or []
        already_found = {h.get("cve") for h in nvd_hits if h.get("cve")}

        # Load CVE.org CVSS + affected data
        db = SessionLocal()
        cveorg_data = {}
        try:
            ds = db.query(models.CveDataset).filter(
                models.CveDataset.workspace_id == ws_id,
                models.CveDataset.kind == "cvedetails_cvss",
                models.CveDataset.enabled == True,
            ).all()
            for d in ds:
                data = load_json(d.path)
                if isinstance(data, dict):
                    cveorg_data = data
                    break
        finally:
            db.close()

        if not cveorg_data:
            return PluginResult()

        # Also load NVD data for summary/refs
        nvd_by_cve = {}
        try:
            db2 = SessionLocal()
            ds2 = db2.query(models.CveDataset).filter(
                models.CveDataset.workspace_id == ws_id,
                models.CveDataset.kind == "nvd_cpe_cve",
                models.CveDataset.enabled == True,
            ).all()
            for d in ds2:
                for item in load_json(d.path) or []:
                    cve_id = item.get("cve")
                    if cve_id:
                        nvd_by_cve[cve_id] = item
            db2.close()
        except Exception:
            pass

        # Build lookup: normalized (vendor, product) → list of CPE candidates
        cand_lookup = {}
        for c in cands:
            vendor = _norm(c.get("vendor", ""))
            product = _norm(c.get("product", ""))
            key = (vendor, product)
            if key not in cand_lookup:
                cand_lookup[key] = []
            cand_lookup[key].append(c)

        # Match CVE.org affected data against detected software
        hits = []
        for cve_id, cve_data in cveorg_data.items():
            if not isinstance(cve_data, dict):
                continue
            if cve_id in already_found:
                continue

            affected_list = cve_data.get("affected", [])
            if not affected_list:
                continue

            for aff in affected_list:
                aff_vendor = _norm(aff.get("vendor", ""))
                aff_product = _norm(aff.get("product", ""))

                # Try exact match first
                matched_cands = cand_lookup.get((aff_vendor, aff_product), [])

                # Try with just product match if vendor differs
                if not matched_cands:
                    for (cv, cp), cl in cand_lookup.items():
                        if cp == aff_product or cv == aff_product:
                            matched_cands = cl
                            break

                for c in matched_cands:
                    installed = c.get("version")
                    if not installed:
                        continue
                    if _version_in_range(installed, aff):
                        fix_version = aff.get("lessThan") or aff.get("lessThanOrEqual", "")
                        nvd_info = nvd_by_cve.get(cve_id, {})
                        hits.append({
                            "cve": cve_id,
                            "summary": nvd_info.get("summary", f"{cve_id} affects {aff.get('vendor', '')} {aff.get('product', '')}"),
                            "severity": cve_data.get("severity", nvd_info.get("severity", "medium")),
                            "cvss": cve_data.get("cvss", nvd_info.get("cvss")),
                            "refs": nvd_info.get("refs", []),
                            "matched_vendor": aff.get("vendor", ""),
                            "matched_product": aff.get("product", ""),
                            "installed_version": installed,
                            "fix_version": fix_version,
                            "confidence": min(c.get("confidence", 0.7), 0.75),
                            "source": "cveorg_affected",
                        })
                        break  # One match per CVE per affected entry

        # Generate findings
        findings = []
        seen_cves = set()
        for h in hits[:500]:
            cve = h["cve"]
            if cve in seen_cves:
                continue
            seen_cves.add(cve)

            fp = stable_fingerprint(target, META.plugin_id, cve, h.get("matched_product", ""))
            fix_ver = h.get("fix_version", "latest")

            description = h.get("summary", "")
            description += (
                f"\n\nMatched via CVE.org affected-product data (not NVD CPE)."
                f"\nAffected: {h['matched_vendor']} {h['matched_product']}"
                f"\nInstalled: {h['installed_version']}"
                f"\nFix: upgrade to {fix_ver} or later"
            )

            remediation = (
                f"[AFFECTED] {h['matched_vendor'].title()} {h['matched_product'].title()} "
                f"version {h['installed_version']}\n\n"
                f"[FIX] Upgrade to version {fix_ver} or later.\n\n"
            )
            if cve.startswith("CVE-"):
                remediation += (
                    f"[CVE DETAILS]\n"
                    f"  - https://nvd.nist.gov/vuln/detail/{cve}\n"
                    f"  - https://www.cve.org/CVERecord?id={cve}\n"
                )

            findings.append(Finding(
                severity=h.get("severity", "medium"),
                plugin_id=META.plugin_id,
                title=f"{cve}: {h['matched_vendor'].title()} {h['matched_product'].title()} "
                      f"{h['installed_version']} (CVE.org match)",
                description=description,
                references=h.get("refs", []),
                evidence=(
                    f"cve={cve} vendor={h['matched_vendor']} product={h['matched_product']} "
                    f"installed={h['installed_version']} fix={fix_ver} "
                    f"source=cveorg_affected cvss={h.get('cvss', 'N/A')}"
                ),
                affected=target,
                fingerprint=fp,
                cvss=h.get("cvss"),
                cve=cve,
                confidence=h.get("confidence", 0.70),
                remediation=remediation,
            ))

        if findings:
            logger.info(
                "CVE.org matcher found %d additional CVEs (not in NVD CPE data)",
                len(findings),
            )

        return PluginResult(
            findings=findings,
            artifacts={"cve.cveorg_hits": hits},
        )
