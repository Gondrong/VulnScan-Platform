"""
testssl.sh integration — comprehensive TLS/SSL security audit.

Tests for protocol support, cipher strength, known vulnerabilities
(Heartbleed, ROBOT, POODLE, CRIME, BREACH, DROWN, FREAK, Logjam),
certificate chain issues, HSTS, OCSP stapling, and more.

Much deeper than the built-in tls.basic plugin.
"""
import asyncio
import json
import logging
import re
import shutil

from app.scanner.plugins.base import Finding, Plugin, PluginMeta, PluginResult
from app.scanner.context import stable_fingerprint

logger = logging.getLogger("vulnscan.plugin.testssl")

META = PluginMeta(
    plugin_id="ext.testssl",
    name="testssl.sh TLS Auditor",
    category="tls",
    provides=["testssl.findings"],
    depends_on=[],
    soft_depends_on=["ext.nmap"],
    enabled_by_default=True,
    timeout_seconds=150.0,
)

# Map testssl severity to our severity levels
_SEV_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "WARN": "medium",
    "INFO": "info",
    "OK": "info",
}

# Known vulnerability IDs from testssl that are high-impact
_VULN_IDS = {
    "heartbleed": ("critical", "Heartbleed (CVE-2014-0160)", "CVE-2014-0160"),
    "CCS": ("high", "CCS Injection (CVE-2014-0224)", "CVE-2014-0224"),
    "ticketbleed": ("high", "Ticketbleed (CVE-2016-9244)", "CVE-2016-9244"),
    "ROBOT": ("high", "ROBOT Attack", None),
    "secure_renego": ("high", "Insecure TLS Renegotiation", None),
    "secure_client_renego": ("medium", "Client-Initiated Renegotiation", None),
    "CRIME_TLS": ("high", "CRIME (TLS compression)", None),
    "BREACH": ("medium", "BREACH (HTTP compression)", None),
    "POODLE_SSL": ("high", "POODLE (SSLv3)", "CVE-2014-3566"),
    "fallback_SCSV": ("medium", "Missing TLS_FALLBACK_SCSV", None),
    "SWEET32": ("medium", "SWEET32 (64-bit block ciphers)", "CVE-2016-2183"),
    "FREAK": ("high", "FREAK (RSA Export Keys)", "CVE-2015-0204"),
    "DROWN": ("high", "DROWN (SSLv2 cross-protocol)", "CVE-2016-0800"),
    "LOGJAM": ("high", "Logjam (DHE Export)", "CVE-2015-4000"),
    "BEAST": ("medium", "BEAST (CBC in TLS 1.0)", "CVE-2011-3389"),
    "LUCKY13": ("medium", "Lucky13 (CBC timing)", "CVE-2013-0169"),
    "winshock": ("critical", "WinShock (CVE-2014-6321)", "CVE-2014-6321"),
    "RC4": ("medium", "RC4 Ciphers Supported", None),
}


def _parse_testssl_json(data: list[dict], target: str) -> list[Finding]:
    """Parse testssl.sh --jsonfile output into findings."""
    findings = []
    seen = set()

    for entry in data:
        eid = entry.get("id", "")
        severity_str = entry.get("severity", "INFO").upper()
        finding_text = entry.get("finding", "")

        # Skip OK / informational results unless they're notable
        if severity_str == "OK" and eid not in _VULN_IDS:
            continue
        if severity_str == "INFO" and eid not in _VULN_IDS:
            continue

        # Dedup
        if eid in seen:
            continue
        seen.add(eid)

        # Check known vulns first
        if eid in _VULN_IDS:
            vuln_sev, vuln_title, cve = _VULN_IDS[eid]
            # Only flag if NOT OK (vulnerable)
            if severity_str in ("OK", "INFO") and "not vulnerable" in finding_text.lower():
                continue
            findings.append(Finding(
                plugin_id=META.plugin_id,
                title=f"[TLS] {vuln_title}",
                severity=vuln_sev,
                description=finding_text,
                evidence=f"test={eid} finding={finding_text[:200]}",
                cve=cve,
                affected=target,
                fingerprint=stable_fingerprint(target, META.plugin_id, eid),
                remediation=f"Patch or reconfigure TLS to mitigate {vuln_title}. Update OpenSSL and disable vulnerable protocols/ciphers.",
                confidence=0.90,
            ))
            continue

        # Generic severity-based findings
        sev = _SEV_MAP.get(severity_str, "info")
        if sev == "info":
            continue  # skip info-level generic entries

        # Protocol issues
        title = f"[TLS] {eid}: {finding_text[:80]}"
        remediation = ""

        if "ssl" in eid.lower() and ("offered" in finding_text.lower()):
            title = f"[TLS] Obsolete protocol: {finding_text[:60]}"
            remediation = "Disable SSLv2/SSLv3 and TLS 1.0/1.1. Only allow TLS 1.2+."
        elif "cipher" in eid.lower() or "NULL" in finding_text or "EXPORT" in finding_text:
            title = f"[TLS] Weak cipher: {finding_text[:60]}"
            remediation = "Remove weak, NULL, and EXPORT ciphers. Use modern cipher suites."
        elif "cert" in eid.lower():
            title = f"[TLS] Certificate issue: {finding_text[:60]}"
            remediation = "Fix certificate chain, use trusted CA, ensure proper validity dates."
        elif "hsts" in eid.lower():
            title = f"[TLS] HSTS: {finding_text[:60]}"
            remediation = "Enable HTTP Strict Transport Security with a long max-age."

        findings.append(Finding(
            plugin_id=META.plugin_id,
            title=title,
            severity=sev,
            description=finding_text,
            evidence=f"test={eid} severity={severity_str}",
            affected=target,
            fingerprint=stable_fingerprint(target, META.plugin_id, eid),
            remediation=remediation or "Review and harden TLS configuration.",
            confidence=0.85,
        ))

    return findings


class Check(Plugin):
    async def run(self, target: str, ctx) -> PluginResult:
        if not shutil.which("testssl.sh"):
            return PluginResult(findings=[Finding(
                plugin_id=META.plugin_id,
                title="testssl.sh not found — skipping TLS audit",
                severity="info",
                evidence="testssl.sh is not installed",
                fingerprint=stable_fingerprint(target, META.plugin_id, "missing"),
            )])

        # Determine TLS-capable ports
        open_ports = ctx.get("net.open_ports", []) or []
        tls_ports = [p for p in open_ports if p in (443, 8443, 4443, 993, 995, 465, 636, 5986, 9443)]
        # If no known TLS ports found, try 443 anyway
        if not tls_ports:
            tls_ports = [443]

        target_raw = ctx.get("target_raw", target)
        effective_timeout = ctx.get("_effective_timeout", META.timeout_seconds)

        # Only scan first 3 TLS ports to stay within budget
        tls_ports = tls_ports[:3]
        all_findings: list[Finding] = []

        for port in tls_ports:
            host_port = f"{target}:{port}"
            json_file = f"/tmp/testssl_{target.replace('.', '_')}_{port}.json"

            cmd = [
                "testssl.sh",
                "--jsonfile", json_file,
                "--sneaky",           # less intrusive
                "--fast",             # skip some redundant tests
                "--ip", "one",        # don't test all IPs
                "--quiet",
                "--color", "0",
                host_port,
            ]

            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                per_port_timeout = effective_timeout / len(tls_ports)
                await asyncio.wait_for(proc.communicate(), timeout=per_port_timeout)
            except asyncio.TimeoutError:
                try:
                    proc.kill()
                except Exception:
                    pass
                all_findings.append(Finding(
                    plugin_id=META.plugin_id,
                    title=f"testssl.sh timed out on {host_port}",
                    severity="info",
                    evidence=f"timeout={per_port_timeout:.0f}s port={port}",
                    affected=target,
                    fingerprint=stable_fingerprint(target, META.plugin_id, "timeout", port),
                ))
                continue
            except Exception as e:
                logger.warning("testssl.sh error on %s: %s", host_port, e)
                continue

            # Parse JSON output
            try:
                import os
                if os.path.exists(json_file):
                    with open(json_file) as f:
                        data = json.load(f)
                    os.unlink(json_file)
                else:
                    continue
            except Exception:
                continue

            if not isinstance(data, list):
                continue

            port_findings = _parse_testssl_json(data, target)
            all_findings.extend(port_findings)

        if not all_findings:
            all_findings.append(Finding(
                plugin_id=META.plugin_id,
                title="testssl.sh: no TLS issues detected",
                severity="info",
                evidence=f"ports_tested={tls_ports}",
                affected=target,
                fingerprint=stable_fingerprint(target, META.plugin_id, "clean"),
            ))

        return PluginResult(
            findings=all_findings,
            artifacts={"testssl.findings": len(all_findings)},
        )
