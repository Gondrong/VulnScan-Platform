"""
subfinder integration — passive subdomain enumeration.

Discovers subdomains using passive sources (crt.sh, VirusTotal, SecurityTrails,
Shodan, Censys, etc.) without sending any traffic to the target. Much broader
coverage than brute-force DNS enumeration.

Only runs when the target is a domain (not an IP address).
"""
import asyncio
import json
import logging
import re
import shutil

from app.scanner.plugins.base import Finding, Plugin, PluginMeta, PluginResult
from app.scanner.context import stable_fingerprint

logger = logging.getLogger("vulnscan.plugin.subfinder")

META = PluginMeta(
    plugin_id="ext.subfinder",
    name="Subfinder Subdomain Enum",
    category="recon",
    provides=["recon.subdomains"],
    depends_on=[],
    enabled_by_default=True,
    timeout_seconds=90.0,
)


def _is_domain(target: str) -> bool:
    """Check if target is a domain (not an IP)."""
    # Strip scheme if present
    t = re.sub(r"^https?://", "", target).split("/")[0].split(":")[0]
    # Simple IP check
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", t):
        return False
    if ":" in t and not t.startswith("["):
        # might be IPv6
        return False
    # Must have at least one dot and no spaces
    return "." in t and " " not in t


def _extract_domain(target: str) -> str:
    """Extract the base domain from a target URL or hostname."""
    t = re.sub(r"^https?://", "", target).split("/")[0].split(":")[0]
    return t


class Check(Plugin):
    async def run(self, target: str, ctx) -> PluginResult:
        if not shutil.which("subfinder"):
            return PluginResult(findings=[Finding(
                plugin_id=META.plugin_id,
                title="subfinder not found — skipping subdomain enum",
                severity="info",
                evidence="subfinder is not installed",
                fingerprint=stable_fingerprint(target, META.plugin_id, "missing"),
            )])

        target_raw = ctx.get("target_raw", target)

        if not _is_domain(target_raw) and not _is_domain(target):
            return PluginResult(findings=[Finding(
                plugin_id=META.plugin_id,
                title="subfinder: skipped (target is IP, not domain)",
                severity="info",
                evidence=f"target={target}",
                fingerprint=stable_fingerprint(target, META.plugin_id, "skip_ip"),
            )])

        domain = _extract_domain(target_raw) if _is_domain(target_raw) else _extract_domain(target)
        effective_timeout = ctx.get("_effective_timeout", META.timeout_seconds)
        options = ctx.get("profile_options", {})
        sf_opts = options.get("subfinder", {})

        cmd = [
            "subfinder",
            "-d", domain,
            "-silent",
            "-jsonl",
            "-timeout", str(sf_opts.get("timeout", 30)),
            "-t", str(sf_opts.get("threads", 10)),
        ]

        # Optional: recursive enumeration
        if sf_opts.get("recursive", False):
            cmd.append("-recursive")

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=effective_timeout
            )
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except Exception:
                pass
            return PluginResult(findings=[Finding(
                plugin_id=META.plugin_id,
                title="subfinder timed out",
                severity="info",
                evidence=f"timeout={effective_timeout}s domain={domain}",
                affected=target,
                fingerprint=stable_fingerprint(target, META.plugin_id, "timeout"),
            )])
        except Exception as e:
            return PluginResult(findings=[Finding(
                plugin_id=META.plugin_id,
                title=f"subfinder error: {e}",
                severity="info",
                evidence=str(e)[:300],
                affected=target,
                fingerprint=stable_fingerprint(target, META.plugin_id, "error"),
            )])

        # Parse JSONL output
        subdomains: list[str] = []
        sources_map: dict[str, list[str]] = {}

        for line in stdout.decode("utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                host = entry.get("host", "")
                source = entry.get("source", "unknown")
            except json.JSONDecodeError:
                # Plain text fallback (some versions output plain hostnames)
                host = line
                source = "unknown"

            if host and host not in subdomains:
                subdomains.append(host)
                sources_map.setdefault(host, []).append(source)

        findings: list[Finding] = []

        # Summary
        findings.append(Finding(
            plugin_id=META.plugin_id,
            title=f"subfinder: {len(subdomains)} subdomains discovered for {domain}",
            severity="info",
            description=f"Passive subdomain enumeration found {len(subdomains)} subdomains.",
            evidence="\n".join(subdomains[:50]) + ("\n..." if len(subdomains) > 50 else ""),
            affected=domain,
            fingerprint=stable_fingerprint(target, META.plugin_id, "summary"),
        ))

        # Flag large attack surface
        if len(subdomains) > 50:
            findings.append(Finding(
                plugin_id=META.plugin_id,
                title=f"Large attack surface: {len(subdomains)} subdomains for {domain}",
                severity="low",
                description=(
                    f"The domain {domain} has {len(subdomains)} publicly known subdomains. "
                    "Each is a potential entry point. Review for decommissioned or shadow IT assets."
                ),
                evidence=f"subdomain_count={len(subdomains)} domain={domain}",
                affected=domain,
                fingerprint=stable_fingerprint(target, META.plugin_id, "large_surface"),
                remediation="Audit all subdomains. Decommission unused ones. Ensure all are monitored.",
            ))

        # Merge with existing DNS enumeration results
        prev_subs = ctx.get("recon.subdomains", []) or []
        merged = list(set(prev_subs + subdomains))

        return PluginResult(
            findings=findings,
            artifacts={"recon.subdomains": merged},
        )
