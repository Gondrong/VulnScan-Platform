"""
CVE Cross-Reference Verifier — correlates CVE matches with OWASP active
scan results to boost or reduce confidence.

If a CVE's CWE maps to an OWASP category that was actively tested:
- Positive OWASP finding → validation_state=validated, confidence=0.85
- OWASP tested but found nothing → validation_state=likely_not_exploitable, confidence=0.15
- OWASP didn't test the category → no change (pass through)
"""
import logging

from app.scanner.plugins.base import Finding, Plugin, PluginMeta, PluginResult
from app.scanner.context import stable_fingerprint

logger = logging.getLogger("vulnscan.cve_verifier")

META = PluginMeta(
    plugin_id="cve.verifier",
    name="CVE Cross-Reference Verifier",
    category="validation",
    depends_on=["cve.match.nvd_cpe", "owasp.web.scanner"],
    soft_depends_on=["cve.match.packages"],
    consumes=["cve.nvd_hits", "cve.package_hits", "owasp.finding_types", "owasp.tested_categories"],
    provides=["cve.verified"],
    enabled_by_default=True,
    timeout_seconds=5.0,
)

# CWE → OWASP category mapping
# Maps common CWE IDs (from NVD CVE descriptions/metadata) to the OWASP
# test categories tracked by owasp_scanner.py.
_CWE_TO_OWASP = {
    # SQL Injection
    "CWE-89": "sqli",
    "CWE-564": "sqli",
    # XSS
    "CWE-79": "xss",
    "CWE-80": "xss",
    # Path Traversal / LFI
    "CWE-22": "lfi",
    "CWE-23": "lfi",
    "CWE-36": "lfi",
    "CWE-98": "lfi",
    # Command Injection
    "CWE-78": "cmdi",
    "CWE-77": "cmdi",
    "CWE-76": "cmdi",
    # SSRF
    "CWE-918": "ssrf",
    # Info Disclosure
    "CWE-200": "info_disclosure",
    "CWE-209": "info_disclosure",
    "CWE-532": "info_disclosure",
    # Cryptographic
    "CWE-311": "crypto",
    "CWE-319": "crypto",
    "CWE-326": "crypto",
    "CWE-327": "crypto",
    # CORS / Misconfiguration
    "CWE-942": "cors",
    "CWE-16": "misconfig",
}

# Keywords in CVE summaries that map to OWASP categories
# Used as fallback when CWE is not available in the NVD hit data.
_SUMMARY_KEYWORDS = {
    "sqli": ["sql injection", "sql query", "sqli"],
    "xss": ["cross-site scripting", "xss", "script injection"],
    "lfi": ["path traversal", "directory traversal", "local file inclusion", "lfi"],
    "cmdi": ["command injection", "os command", "shell command"],
    "ssrf": ["server-side request forgery", "ssrf"],
    "info_disclosure": ["information disclosure", "information leak", "sensitive data exposure"],
    "crypto": ["plaintext", "unencrypted", "cryptographic"],
}


def _cve_to_owasp_category(hit: dict) -> str | None:
    """Map a CVE/NVD hit to an OWASP test category."""
    # Try CWE mapping first (if available in the dataset)
    cwe = hit.get("cwe") or ""
    if cwe and cwe in _CWE_TO_OWASP:
        return _CWE_TO_OWASP[cwe]

    # Fallback: keyword matching in summary
    summary = (hit.get("summary") or "").lower()
    for category, keywords in _SUMMARY_KEYWORDS.items():
        if any(kw in summary for kw in keywords):
            return category

    return None


class Check(Plugin):
    async def run(self, target, ctx):
        nvd_hits = ctx.get("cve.nvd_hits", []) or []
        pkg_hits = ctx.get("cve.package_hits", []) or []
        all_hits = nvd_hits + pkg_hits

        if not all_hits:
            return PluginResult(artifacts={"cve.verified": []})

        owasp_finding_types = set(ctx.get("owasp.finding_types", []) or [])
        owasp_tested = set(ctx.get("owasp.tested_categories", []) or [])

        if not owasp_tested:
            # OWASP scanner didn't run or had no HTTP target — can't cross-reference
            return PluginResult(artifacts={"cve.verified": []})

        findings = []
        verified = []

        for hit in all_hits:
            cve = hit.get("cve", "")
            if not cve or not cve.startswith("CVE-"):
                continue

            owasp_cat = _cve_to_owasp_category(hit)
            if not owasp_cat:
                continue  # No mapping — can't cross-reference

            if owasp_cat not in owasp_tested:
                continue  # OWASP didn't test this category — no evidence either way

            fp = stable_fingerprint(target, META.plugin_id, cve, owasp_cat)
            if not ctx.dedup(fp):
                continue

            if owasp_cat in owasp_finding_types:
                # Positive cross-reference: OWASP found a vulnerability in this category
                v_state = "validated"
                v_method = "owasp_cross_reference"
                v_confidence = 0.85
                severity = hit.get("severity", "high")
                title = f"Validated {cve}: confirmed by OWASP {owasp_cat} scan"
                desc = (
                    f"{cve} is correlated with OWASP category '{owasp_cat}', and the "
                    f"OWASP active scanner independently confirmed a {owasp_cat} vulnerability "
                    f"on this target. This significantly increases confidence that this CVE "
                    f"is exploitable."
                )
            else:
                # Negative cross-reference: OWASP tested but found nothing
                v_state = "likely_not_exploitable"
                v_method = "owasp_negative_cross_reference"
                v_confidence = 0.15
                severity = hit.get("severity", "low")
                title = f"Low-confidence {cve}: OWASP {owasp_cat} scan found no evidence"
                desc = (
                    f"{cve} is correlated with OWASP category '{owasp_cat}', but the "
                    f"OWASP active scanner tested for {owasp_cat} vulnerabilities and found "
                    f"none on this target. This reduces confidence that this CVE is exploitable "
                    f"in the current configuration."
                )

            verified.append({
                "cve": cve,
                "owasp_category": owasp_cat,
                "validation_state": v_state,
                "confidence": v_confidence,
            })

            findings.append(Finding(
                severity=severity,
                plugin_id=META.plugin_id,
                title=title,
                description=desc,
                evidence=(
                    f"cve={cve} owasp_category={owasp_cat} "
                    f"owasp_detected={'yes' if owasp_cat in owasp_finding_types else 'no'} "
                    f"validation_state={v_state} validation_method={v_method}"
                ),
                affected=target,
                fingerprint=fp,
                cve=cve,
                cvss=hit.get("cvss"),
                confidence=v_confidence,
                references=hit.get("refs", []),
            ))

        return PluginResult(findings=findings, artifacts={"cve.verified": verified})

