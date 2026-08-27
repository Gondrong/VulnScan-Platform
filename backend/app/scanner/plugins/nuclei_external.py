"""
Nuclei integration — runs ProjectDiscovery Nuclei for template-based vuln scanning.

Nuclei scans web targets using its community template library (CVEs, misconfigs,
exposures, technologies). Runs after HTTP fingerprinting so it targets the correct
ports/schemes.

Nuclei binary + templates are installed in the Docker image (see Dockerfile).
"""
import asyncio
import json
import logging
import re
import shutil

from app.scanner.plugins.base import Finding, Plugin, PluginMeta, PluginResult
from app.scanner.context import stable_fingerprint

logger = logging.getLogger("vulnscan.plugin.nuclei")

META = PluginMeta(
    plugin_id="ext.nuclei",
    name="Nuclei Template Scanner",
    category="web",
    provides=["nuclei.findings"],
    depends_on=[],
    soft_depends_on=["fingerprint.http", "ext.nmap"],
    enabled_by_default=True,
    timeout_seconds=180.0,
)

_SEV_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
    "unknown": "info",
}


def _extract_cve(info: dict) -> str | None:
    """Try to extract a CVE ID from nuclei result info block."""
    # classification.cve-id field
    classification = info.get("classification", {}) or {}
    cve_ids = classification.get("cve-id") or []
    if isinstance(cve_ids, list) and cve_ids:
        return cve_ids[0]
    if isinstance(cve_ids, str) and cve_ids:
        return cve_ids

    # Fallback: scan references for CVE pattern
    refs = info.get("reference") or []
    if isinstance(refs, list):
        for ref in refs:
            m = re.search(r"(CVE-\d{4}-\d+)", str(ref), re.I)
            if m:
                return m.group(1).upper()
    return None


def _extract_cvss(info: dict) -> float | None:
    """Extract CVSS score from nuclei classification."""
    classification = info.get("classification", {}) or {}
    score = classification.get("cvss-score")
    if score is not None:
        try:
            return float(score)
        except (ValueError, TypeError):
            pass

    metrics = classification.get("cvss-metrics")
    if metrics:
        # Nuclei sometimes has score in metrics string
        m = re.search(r"(\d+\.?\d*)", str(metrics))
        if m:
            try:
                return float(m.group(1))
            except ValueError:
                pass
    return None


def _build_target_url(target: str, ctx) -> str:
    """Build the URL to pass to nuclei based on scan context."""
    target_raw = ctx.get("target_raw", target)
    if re.match(r"^https?://", target_raw, re.I):
        return target_raw

    # Check if HTTP fingerprint found a scheme
    scheme = ctx.get("target_scheme", "")
    if scheme:
        return f"{scheme}://{target}"

    # Default: try HTTPS first, nuclei handles fallback
    return f"https://{target}"


class Check(Plugin):
    async def run(self, target: str, ctx) -> PluginResult:
        if not shutil.which("nuclei"):
            return PluginResult(findings=[Finding(
                plugin_id=META.plugin_id,
                title="Nuclei binary not found — skipping template scan",
                severity="info",
                evidence="nuclei is not installed in this container",
                fingerprint=stable_fingerprint(target, META.plugin_id, "missing"),
            )])

        scan_type = ctx.get("scan_type", "internal")
        options = ctx.get("profile_options", {})
        nuclei_opts = options.get("nuclei", {})
        effective_timeout = ctx.get("_effective_timeout", META.timeout_seconds)

        target_url = _build_target_url(target, ctx)

        # Build nuclei command
        cmd = [
            "nuclei",
            "-u", target_url,
            "-jsonl",                  # JSON Lines output
            "-silent",                 # suppress banner/progress
            "-no-color",
            "-timeout", "10",          # per-request timeout
            "-retries", "1",
            "-rate-limit", "100",      # requests per second cap
            "-bulk-size", "25",
            "-concurrency", "25",
            "-no-interactsh",          # disable OOB testing (needs external server)
            "-duc",                    # no template update check: it reaches out
                                       # to GitHub on every run and can stall for
                                       # minutes before the scan even starts
        ]

        # Severity filter — default to critical,high,medium for speed
        severities = nuclei_opts.get("severity", "critical,high,medium,low")
        cmd += ["-severity", severities]

        # Template tags filter (optional)
        tags = nuclei_opts.get("tags", "")
        if tags:
            cmd += ["-tags", tags]

        # Exclude tags (optional, e.g. dos)
        exclude_tags = nuclei_opts.get("exclude_tags", "dos,fuzz")
        if exclude_tags:
            cmd += ["-etags", exclude_tags]

        # Template types filter (optional)
        template_types = nuclei_opts.get("types", "")
        if template_types:
            cmd += ["-type", template_types]

        # For internal scans, also scan non-standard ports found by nmap
        open_ports = ctx.get("net.open_ports", []) or []
        http_ports = [p for p in open_ports if p not in (80, 443)]
        if http_ports and len(http_ports) <= 10:
            # Add extra port targets for nuclei
            for p in http_ports:
                # Nuclei can scan multiple targets if we add them
                for scheme in ("http", "https"):
                    cmd += ["-u", f"{scheme}://{target}:{p}"]

        logger.info("Nuclei cmd: %s", " ".join(cmd[:15]) + "...")

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=effective_timeout,
            )
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except Exception:
                pass
            return PluginResult(findings=[Finding(
                plugin_id=META.plugin_id,
                title="Nuclei scan timed out",
                severity="info",
                evidence=f"timeout={effective_timeout}s",
                affected=target,
                fingerprint=stable_fingerprint(target, META.plugin_id, "timeout"),
                remediation="Try narrowing severity/tags or increase SCAN_BUDGET_SECONDS.",
            )])
        except Exception as e:
            return PluginResult(findings=[Finding(
                plugin_id=META.plugin_id,
                title=f"Nuclei execution error: {e}",
                severity="info",
                evidence=str(e)[:300],
                affected=target,
                fingerprint=stable_fingerprint(target, META.plugin_id, "error"),
            )])

        # Parse JSONL output
        findings: list[Finding] = []
        seen_templates: set[str] = set()

        for line in stdout.decode("utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                result = json.loads(line)
            except json.JSONDecodeError:
                continue

            template_id = result.get("template-id", "unknown")
            info = result.get("info", {}) or {}
            name = info.get("name", template_id)
            severity = _SEV_MAP.get(
                (info.get("severity") or "info").lower(), "info"
            )
            matched_at = result.get("matched-at", target_url)
            matcher_name = result.get("matcher-name", "")
            extracted = result.get("extracted-results") or []

            # Deduplicate by template+matched_at
            dedup_key = f"{template_id}:{matched_at}"
            if dedup_key in seen_templates:
                continue
            seen_templates.add(dedup_key)

            cve_id = _extract_cve(info)
            cvss = _extract_cvss(info)
            description = info.get("description", "")
            remediation = info.get("remediation", "")
            refs = info.get("reference") or []
            if isinstance(refs, str):
                refs = [refs]

            # Build evidence string
            evidence_parts = [f"template={template_id}"]
            if matched_at:
                evidence_parts.append(f"matched_at={matched_at}")
            if matcher_name:
                evidence_parts.append(f"matcher={matcher_name}")
            if extracted:
                evidence_parts.append(f"extracted={extracted[:3]}")
            evidence = " ".join(evidence_parts)

            findings.append(Finding(
                plugin_id=META.plugin_id,
                title=f"[Nuclei] {name}",
                severity=severity,
                description=description,
                evidence=evidence[:1000],
                remediation=remediation,
                references=refs[:10] if isinstance(refs, list) else [],
                cve=cve_id,
                cvss=cvss,
                affected=matched_at or target,
                fingerprint=stable_fingerprint(target, META.plugin_id, template_id, matched_at),
                confidence=0.85 if severity in ("critical", "high") else 0.75,
            ))

        # Summary finding
        if findings:
            sev_counts = {}
            for f in findings:
                sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
            summary = ", ".join(f"{v} {k}" for k, v in sorted(sev_counts.items()))
            findings.insert(0, Finding(
                plugin_id=META.plugin_id,
                title=f"Nuclei scan: {len(findings)} issues found ({summary})",
                severity="info",
                evidence=f"templates_matched={len(seen_templates)} target={target_url}",
                affected=target,
                fingerprint=stable_fingerprint(target, META.plugin_id, "summary"),
            ))
        else:
            findings.append(Finding(
                plugin_id=META.plugin_id,
                title="Nuclei scan completed — no issues found",
                severity="info",
                evidence=f"target={target_url} severities={severities}",
                affected=target,
                fingerprint=stable_fingerprint(target, META.plugin_id, "clean"),
            ))

        return PluginResult(
            findings=findings,
            artifacts={"nuclei.findings": len(findings)},
        )
