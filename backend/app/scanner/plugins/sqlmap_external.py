"""
sqlmap integration — advanced SQL injection detection and exploitation testing.

Runs sqlmap in safe, non-destructive mode (--batch --level 1 --risk 1) to detect
SQL injection vulnerabilities. Much more thorough than the built-in deep_sqli
plugin, with 100+ bypass techniques, time-based blind, boolean blind, error-based,
UNION-based, and stacked queries.

Uses discovered URLs from ffuf/dir_crawl and form targets from HTTP fingerprinting.
"""
import asyncio
import json
import logging
import os
import re
import shutil
import tempfile

from app.scanner.plugins.base import Finding, Plugin, PluginMeta, PluginResult
from app.scanner.context import stable_fingerprint

logger = logging.getLogger("vulnscan.plugin.sqlmap")

META = PluginMeta(
    plugin_id="ext.sqlmap",
    name="sqlmap SQL Injection Scanner",
    category="web",
    provides=["sqlmap.findings"],
    depends_on=[],
    soft_depends_on=["fingerprint.http", "ext.ffuf", "recon.directory.crawl"],
    enabled_by_default=True,
    timeout_seconds=180.0,
)

# sqlmap technique types
_TECHNIQUE_NAMES = {
    "B": "Boolean-based blind",
    "E": "Error-based",
    "U": "UNION query",
    "S": "Stacked queries",
    "T": "Time-based blind",
    "Q": "Inline queries",
}


def _find_sqlmap() -> str | None:
    """Locate sqlmap binary or script."""
    # Check common locations
    for path in [
        "/usr/local/bin/sqlmap",
        "/opt/sqlmap/sqlmap.py",
        "/usr/bin/sqlmap",
    ]:
        if os.path.exists(path):
            return path
    return shutil.which("sqlmap")


def _build_target_urls(target: str, ctx) -> list[str]:
    """Build list of URLs to test for SQL injection."""
    urls: list[str] = []

    target_raw = ctx.get("target_raw", target)
    scheme = ctx.get("target_scheme", "")

    # Primary target URL
    if re.match(r"^https?://", target_raw, re.I):
        base_url = target_raw.rstrip("/")
    elif scheme:
        base_url = f"{scheme}://{target}"
    else:
        base_url = f"https://{target}"

    urls.append(base_url)

    # Add discovered directories that might have parameters
    directories = ctx.get("recon.directories", []) or []
    for d in directories[:20]:
        path = d.lstrip("/")
        full = f"{base_url}/{path}"
        if full not in urls:
            urls.append(full)

    return urls


def _parse_sqlmap_output(output_dir: str, target: str) -> list[Finding]:
    """Parse sqlmap output directory for results."""
    findings = []

    # sqlmap writes results to output_dir/target_host/
    if not os.path.isdir(output_dir):
        return findings

    for root, dirs, files in os.walk(output_dir):
        for fname in files:
            fpath = os.path.join(root, fname)

            # Parse the log file for injection points
            if fname == "log":
                try:
                    with open(fpath, "r") as f:
                        content = f.read()
                except Exception:
                    continue

                # Extract injection results
                # sqlmap log format shows parameter, type, and payload
                injection_blocks = re.split(r"---\n", content)
                for block in injection_blocks:
                    param_match = re.search(r"Parameter:\s+(.+?)(?:\s+\()", block)
                    type_match = re.search(r"Type:\s+(.+)", block)
                    title_match = re.search(r"Title:\s+(.+)", block)
                    payload_match = re.search(r"Payload:\s+(.+)", block)

                    if param_match and type_match:
                        param = param_match.group(1).strip()
                        inj_type = type_match.group(1).strip()
                        title_str = title_match.group(1).strip() if title_match else inj_type
                        payload = payload_match.group(1).strip() if payload_match else ""

                        # Determine severity based on injection type
                        sev = "high"
                        if "time-based" in inj_type.lower() or "blind" in inj_type.lower():
                            sev = "high"
                        if "stacked" in inj_type.lower() or "UNION" in inj_type.upper():
                            sev = "critical"

                        findings.append(Finding(
                            plugin_id=META.plugin_id,
                            title=f"[sqlmap] SQL Injection: {param} ({inj_type})",
                            severity=sev,
                            description=(
                                f"sqlmap confirmed SQL injection in parameter '{param}'. "
                                f"Type: {title_str}"
                            ),
                            evidence=f"parameter={param} type={inj_type} payload={payload[:200]}",
                            affected=target,
                            fingerprint=stable_fingerprint(target, META.plugin_id, param, inj_type),
                            remediation=(
                                "Use parameterized queries (prepared statements) for ALL database interactions. "
                                "Never concatenate user input into SQL strings. "
                                "Apply input validation and use an ORM where possible."
                            ),
                            confidence=0.95,
                        ))

            # Parse target.txt for identified URLs
            if fname == "target.txt":
                try:
                    with open(fpath) as f:
                        for line in f:
                            line = line.strip()
                            if line and "(" in line:
                                # Format: URL (METHOD)
                                findings.append(Finding(
                                    plugin_id=META.plugin_id,
                                    title=f"[sqlmap] Tested target: {line[:80]}",
                                    severity="info",
                                    evidence=line[:300],
                                    affected=target,
                                    fingerprint=stable_fingerprint(target, META.plugin_id, "target", line[:80]),
                                ))
                except Exception:
                    pass

    return findings


class Check(Plugin):
    async def run(self, target: str, ctx) -> PluginResult:
        sqlmap_path = _find_sqlmap()
        if not sqlmap_path:
            return PluginResult(findings=[Finding(
                plugin_id=META.plugin_id,
                title="sqlmap not found — skipping SQL injection testing",
                severity="info",
                evidence="sqlmap is not installed",
                fingerprint=stable_fingerprint(target, META.plugin_id, "missing"),
            )])

        effective_timeout = ctx.get("_effective_timeout", META.timeout_seconds)
        options = ctx.get("profile_options", {})
        sqlmap_opts = options.get("sqlmap", {})

        target_urls = _build_target_urls(target, ctx)
        if not target_urls:
            return PluginResult(findings=[Finding(
                plugin_id=META.plugin_id,
                title="sqlmap: no URLs to test",
                severity="info",
                evidence="No HTTP URLs found",
                fingerprint=stable_fingerprint(target, META.plugin_id, "no_urls"),
            )])

        output_dir = tempfile.mkdtemp(prefix="sqlmap_")
        all_findings: list[Finding] = []

        # Determine if sqlmap_path is a .py file (needs python interpreter)
        is_py = sqlmap_path.endswith(".py")
        per_url_timeout = effective_timeout / max(len(target_urls[:5]), 1)

        for url in target_urls[:5]:  # Cap at 5 URLs
            cmd = []
            if is_py:
                cmd = ["python3", sqlmap_path]
            else:
                cmd = [sqlmap_path]

            cmd += [
                "-u", url,
                "--batch",              # non-interactive
                "--output-dir", output_dir,
                "--level", str(sqlmap_opts.get("level", 1)),
                "--risk", str(sqlmap_opts.get("risk", 1)),
                "--threads", str(sqlmap_opts.get("threads", 3)),
                "--timeout", "15",
                "--retries", "1",
                "--crawl", str(sqlmap_opts.get("crawl", 2)),
                "--forms",              # auto-parse forms
                "--smart",              # only test params with heuristic evidence
                "--tamper", sqlmap_opts.get("tamper", "space2comment"),
            ]

            # Safe mode: don't do heavy stuff by default
            if not sqlmap_opts.get("aggressive", False):
                cmd += ["--safe-url", url, "--safe-freq", "3"]

            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=per_url_timeout
                )

                # Check stdout for quick indicators
                out_text = stdout.decode("utf-8", errors="replace")
                if "sqlmap identified the following injection" in out_text:
                    logger.info("sqlmap found injection on %s", url)
                elif "all tested parameters do not appear to be injectable" in out_text:
                    logger.info("sqlmap: no injection on %s", url)

            except asyncio.TimeoutError:
                try:
                    proc.kill()
                except Exception:
                    pass
                all_findings.append(Finding(
                    plugin_id=META.plugin_id,
                    title=f"sqlmap timed out on {url[:60]}",
                    severity="info",
                    evidence=f"timeout={per_url_timeout:.0f}s url={url}",
                    affected=target,
                    fingerprint=stable_fingerprint(target, META.plugin_id, "timeout", url),
                ))
                continue
            except Exception as e:
                logger.warning("sqlmap error on %s: %s", url, e)
                continue

        # Parse all results from output directory
        parsed = _parse_sqlmap_output(output_dir, target)
        all_findings.extend(parsed)

        # Cleanup
        try:
            import shutil as _shutil
            _shutil.rmtree(output_dir, ignore_errors=True)
        except Exception:
            pass

        # Count confirmed injections (non-info findings)
        confirmed = [f for f in all_findings if f.severity != "info"]

        # Summary
        all_findings.insert(0, Finding(
            plugin_id=META.plugin_id,
            title=f"sqlmap: {len(confirmed)} SQL injection(s) found ({len(target_urls[:5])} URLs tested)",
            severity="critical" if confirmed else "info",
            evidence=f"urls_tested={len(target_urls[:5])} confirmed_injections={len(confirmed)}",
            affected=target,
            fingerprint=stable_fingerprint(target, META.plugin_id, "summary"),
        ))

        return PluginResult(
            findings=all_findings,
            artifacts={"sqlmap.findings": len(confirmed)},
        )
