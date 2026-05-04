"""
Infrastructure-as-Code Scanner — orchestrator.

Standalone-only plugin (not registered in the engine plugin loader).
Invoked from /scan/iac/jobs via worker_tasks.run_scan_job when a scan
job has scan_type == "iac".

config shape:
  {
    "archive_b64": "...",         # base64 of zip archive OR single file
    "filename":    "infra.zip",
    "kinds":       ["terraform", "kubernetes", ...],   # optional filter
  }
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any

from app.scanner.plugins.base import Finding
from app.scanner.context import stable_fingerprint

from .parser import parse_upload, decode_archive, ParsedFile
from .rules import CHECKS, RuleHit

logger = logging.getLogger("vulnscan.iac.orchestrator")


_KIND_LABELS = {
    "terraform":      "Terraform / HCL",
    "dockerfile":     "Dockerfile",
    "kubernetes":     "Kubernetes manifest",
    "compose":        "docker-compose",
    "cloudformation": "CloudFormation",
    "helm_values":    "Helm values.yaml",
}


def _hit_to_finding(hit: RuleHit, file_path: str, kind: str) -> Finding:
    affected = f"{kind}:{file_path}" + (f":{hit.line}" if hit.line else "")
    refs = []
    if hit.framework:
        refs.append(hit.framework)
    return Finding(
        plugin_id=f"iac.{kind}.{hit.rule_id.split('.')[-1]}",
        title=hit.title,
        severity=hit.severity,
        description=hit.description,
        remediation=hit.remediation,
        evidence=hit.evidence,
        affected=affected,
        fingerprint=stable_fingerprint(file_path, hit.rule_id, hit.line),
        references=refs,
        confidence=hit.confidence,
    )


class Check:
    """IaC scanner — standalone orchestrator only."""

    async def run_standalone(
        self, config: dict, progress_callback=None,
    ) -> list[Finding]:
        archive_b64 = config.get("archive_b64") or ""
        filename = config.get("filename") or "upload"
        kind_filter = set(config.get("kinds") or [])

        if not archive_b64:
            raise ValueError("iac_scanner config requires 'archive_b64'")

        raw = decode_archive(archive_b64)
        if not raw:
            raise ValueError("Could not decode archive_b64 — not valid base64")

        files = parse_upload(filename, raw)

        # Filter to files we know how to check
        scannable = [f for f in files if f.kind in CHECKS]
        if kind_filter:
            scannable = [f for f in scannable if f.kind in kind_filter]

        all_findings: list[Finding] = []
        total = max(len(scannable), 1)

        # Scan summary finding (always emitted, even if no scannable files)
        kind_breakdown: dict[str, int] = {}
        for f in files:
            kind_breakdown[f.kind] = kind_breakdown.get(f.kind, 0) + 1

        all_findings.append(Finding(
            plugin_id="iac.summary",
            title=f"IaC scan: {len(files)} files ingested ({len(scannable)} scannable)",
            severity="info",
            description=(
                "Inventory of files parsed from the upload. Files marked 'unknown' "
                "did not match any supported IaC format (Terraform, Dockerfile, "
                "Kubernetes, docker-compose, CloudFormation, Helm values)."
            ),
            evidence="\n".join(
                f"  {kind:18s}  {count} file(s)"
                for kind, count in sorted(kind_breakdown.items())
            ) or "  (no files parsed)",
            affected=filename,
            fingerprint=stable_fingerprint(filename, "iac.summary", len(files)),
            remediation=(
                "If files are reported as 'unknown', ensure they have a recognized "
                "extension (.tf, .yaml/.yml, .json) or filename (Dockerfile, "
                "docker-compose.yml). For complex monorepos, scan one IaC subtree at a time."
            ),
        ))

        for step, pf in enumerate(scannable, start=1):
            check_fn = CHECKS.get(pf.kind)
            if not check_fn:
                continue

            label = _KIND_LABELS.get(pf.kind, pf.kind)
            if progress_callback:
                try:
                    _r = progress_callback(step, total, f"iac.{pf.kind}", f"{label}: {pf.path}", "running")
                    if asyncio.iscoroutine(_r):
                        await _r
                except Exception:
                    pass

            try:
                hits = check_fn(pf.path, pf.content)
            except Exception as e:
                logger.warning("IaC check failed for %s (%s): %s", pf.path, pf.kind, e)
                hits = []

            for hit in hits:
                all_findings.append(_hit_to_finding(hit, pf.path, pf.kind))

            if progress_callback:
                try:
                    _r = progress_callback(step, total, f"iac.{pf.kind}", f"{label}: {pf.path}", "done")
                    if asyncio.iscoroutine(_r):
                        await _r
                except Exception:
                    pass

        return all_findings

    async def run(self, target: str, ctx: Any) -> Any:
        """
        Engine-mode placeholder. The IaC scanner is upload-driven so it never
        runs as part of a normal scan_target() flow — but we implement run()
        to satisfy the Plugin protocol if it's ever loaded.
        """
        from app.scanner.plugins.base import PluginResult
        return PluginResult(findings=[], artifacts={})
