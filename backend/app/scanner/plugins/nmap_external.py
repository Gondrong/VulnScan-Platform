"""
Nmap external integration — runs the real nmap binary for service/version detection.

Provides the same artifacts as the built-in port scanners (net.open_ports,
net.service_banners) so downstream plugins consume them transparently.

Nmap is installed in the Docker image (see Dockerfile).
"""
import asyncio
import re
import shutil
import xml.etree.ElementTree as ET

from app.scanner.plugins.base import Finding, Plugin, PluginMeta, PluginResult
from app.scanner.context import stable_fingerprint

META = PluginMeta(
    plugin_id="ext.nmap",
    name="Nmap Service Scanner",
    category="network",
    provides=["net.open_ports", "net.service_banners", "nmap.raw_xml"],
    depends_on=[],
    enabled_by_default=True,
    timeout_seconds=120.0,
)

# Known risky services — generate explicit findings
_RISKY = {
    21: ("ftp", "high", "FTP transmits credentials in plaintext. Use SFTP or FTPS instead."),
    23: ("telnet", "critical", "Telnet transmits credentials in plaintext. Disable and use SSH."),
    161: ("snmp", "medium", "SNMP exposed. Ensure SNMPv3 with authentication, not v1/v2c."),
    445: ("smb", "medium", "SMB exposed. Ensure SMBv1 is disabled and access is restricted."),
    512: ("rexec", "high", "Remote execution service. Disable if not needed."),
    513: ("rlogin", "high", "rlogin allows remote login without encryption. Use SSH."),
    514: ("rsh", "high", "Remote shell has no encryption. Disable and use SSH."),
    2375: ("docker", "critical", "Docker API exposed without TLS! Use TLS (port 2376)."),
    5900: ("vnc", "high", "VNC exposed. Use SSH tunneling and strong auth."),
    6379: ("redis", "high", "Redis exposed. Bind to localhost and enable AUTH."),
    9200: ("elasticsearch", "high", "Elasticsearch exposed. Enable X-Pack security."),
    11211: ("memcached", "high", "Memcached exposed. Bind to localhost."),
    27017: ("mongodb", "high", "MongoDB exposed. Enable authentication."),
}


def _parse_nmap_xml(xml_text: str, target: str) -> tuple[list[Finding], list[int], dict[int, str]]:
    """Parse nmap -oX output into findings + artifacts."""
    findings: list[Finding] = []
    open_ports: list[int] = []
    banners: dict[int, str] = {}

    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return findings, open_ports, banners

    for host in root.findall(".//host"):
        # OS detection (if available)
        osmatch = host.find(".//osmatch")
        os_info = ""
        if osmatch is not None:
            os_info = f"{osmatch.get('name', '')} ({osmatch.get('accuracy', '')}%)"

        for port_el in host.findall(".//port"):
            portid = int(port_el.get("portid", 0))
            proto = port_el.get("protocol", "tcp")
            state_el = port_el.find("state")
            service_el = port_el.find("service")

            if state_el is None or state_el.get("state") != "open":
                continue

            open_ports.append(portid)

            svc_name = service_el.get("name", "unknown") if service_el else "unknown"
            svc_product = service_el.get("product", "") if service_el else ""
            svc_version = service_el.get("version", "") if service_el else ""
            svc_extra = service_el.get("extrainfo", "") if service_el else ""

            banner_parts = [p for p in [svc_product, svc_version, svc_extra] if p]
            banner = " ".join(banner_parts)
            if banner:
                banners[portid] = banner

            # Risky service finding
            if portid in _RISKY:
                rname, sev, remed = _RISKY[portid]
                findings.append(Finding(
                    plugin_id=META.plugin_id,
                    title=f"Risky service exposed: {rname} on port {portid}",
                    severity=sev,
                    description=f"Port {portid} ({rname}) is open and accessible.",
                    evidence=f"port={portid} service={svc_name} banner={banner[:120]}",
                    affected=target,
                    fingerprint=stable_fingerprint(target, META.plugin_id, "risky", portid),
                    remediation=remed,
                    confidence=0.95,
                ))

        # Nmap script results (vuln scripts, ssl-*, etc.)
        for script in host.findall(".//script"):
            script_id = script.get("id", "")
            output = script.get("output", "")

            # ssl-cert expiry
            if script_id == "ssl-cert" and "Not valid after" in output:
                findings.append(Finding(
                    plugin_id=META.plugin_id,
                    title="TLS certificate details detected by Nmap",
                    severity="info",
                    evidence=output[:500],
                    affected=target,
                    fingerprint=stable_fingerprint(target, META.plugin_id, "ssl-cert"),
                ))

            # vulners / vulscan script output
            if script_id in ("vulners", "vulscan"):
                # Extract CVE references
                cves = re.findall(r"(CVE-\d{4}-\d+)", output)
                for cve in cves[:10]:  # cap at 10
                    findings.append(Finding(
                        plugin_id=META.plugin_id,
                        title=f"[Nmap vulners] {cve}",
                        severity="high",
                        evidence=f"script={script_id} cve={cve}",
                        cve=cve,
                        affected=target,
                        fingerprint=stable_fingerprint(target, META.plugin_id, "vulners", cve),
                        confidence=0.70,
                    ))

    open_ports.sort()

    # Summary finding
    port_lines = []
    for p in open_ports:
        b = banners.get(p, "")
        line = f"  {p}/tcp  open  {b}" if b else f"  {p}/tcp  open"
        port_lines.append(line)

    findings.insert(0, Finding(
        plugin_id=META.plugin_id,
        title=f"Nmap scan: {len(open_ports)} open ports detected",
        severity="info",
        evidence=(
            f"NMAP SCAN RESULTS ({len(open_ports)} open ports)\n"
            f"Target: {target}\n"
            + (f"OS: {os_info}\n" if os_info else "")
            + "\n".join(port_lines)
        ),
        affected=target,
        fingerprint=stable_fingerprint(target, META.plugin_id, "summary"),
        remediation=(
            "Review all open ports and close unnecessary services. "
            "Use firewall rules to restrict access."
        ),
    ))

    if len(open_ports) > 20:
        findings.append(Finding(
            plugin_id=META.plugin_id,
            title=f"Excessive open ports: {len(open_ports)} services exposed",
            severity="medium",
            evidence=f"open_port_count={len(open_ports)}",
            affected=target,
            fingerprint=stable_fingerprint(target, META.plugin_id, "excessive_ports"),
            remediation="Reduce the attack surface by closing unnecessary ports.",
        ))

    return findings, open_ports, banners


class Check(Plugin):
    async def run(self, target: str, ctx) -> PluginResult:
        if not shutil.which("nmap"):
            return PluginResult(findings=[Finding(
                plugin_id=META.plugin_id,
                title="Nmap binary not found — skipping external scan",
                severity="info",
                evidence="nmap is not installed in this container",
                fingerprint=stable_fingerprint(target, META.plugin_id, "missing"),
            )])

        scan_type = ctx.get("scan_type", "internal")
        options = ctx.get("profile_options", {})
        nmap_opts = options.get("nmap", {})
        effective_timeout = ctx.get("_effective_timeout", META.timeout_seconds)

        # Build nmap command
        mode = nmap_opts.get("mode", "top100")
        cmd = ["nmap", "-sV", "-oX", "-", "--noninteractive"]

        if mode == "full":
            cmd += ["-p-"]
        elif mode == "top1000":
            cmd += ["--top-ports", "1000"]
        else:
            cmd += ["--top-ports", "100"]

        # Timing: T3 default, T4 for external (more aggressive retries
        # through firewalls), respect user override
        timing = nmap_opts.get("timing", "T4" if scan_type == "external" else "T3")
        cmd += [f"-{timing}"]

        # Extra user-supplied nmap args (safe subset)
        extra = nmap_opts.get("extra_args", "")
        if extra:
            # Only allow safe flags — block dangerous ones
            blocked = {"-iL", "--script-args", "--script", "-oN", "-oG", "-oS", "-oA"}
            for arg in extra.split():
                if arg not in blocked and not arg.startswith("--script"):
                    cmd.append(arg)

        cmd.append(target)

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
                title="Nmap scan timed out",
                severity="info",
                evidence=f"timeout={effective_timeout}s mode={mode}",
                affected=target,
                fingerprint=stable_fingerprint(target, META.plugin_id, "timeout"),
                remediation="Try a smaller port range or increase SCAN_BUDGET_SECONDS.",
            )])
        except Exception as e:
            return PluginResult(findings=[Finding(
                plugin_id=META.plugin_id,
                title=f"Nmap execution error: {e}",
                severity="info",
                evidence=str(e)[:300],
                affected=target,
                fingerprint=stable_fingerprint(target, META.plugin_id, "error"),
            )])

        xml_output = stdout.decode("utf-8", errors="replace")

        if proc.returncode != 0 and not xml_output.strip():
            return PluginResult(findings=[Finding(
                plugin_id=META.plugin_id,
                title="Nmap scan failed",
                severity="info",
                evidence=stderr.decode("utf-8", errors="replace")[:500],
                affected=target,
                fingerprint=stable_fingerprint(target, META.plugin_id, "failed"),
            )])

        findings, open_ports, banners = _parse_nmap_xml(xml_output, target)

        # Merge with ports already discovered by built-in scanners
        prev_ports = ctx.get("net.open_ports", []) or []
        prev_banners = ctx.get("net.service_banners", {}) or {}
        merged_ports = sorted(set(prev_ports + open_ports))
        merged_banners = {**prev_banners, **banners}  # nmap banners take precedence

        return PluginResult(
            findings=findings,
            artifacts={
                "net.open_ports": merged_ports,
                "net.service_banners": merged_banners,
                "nmap.raw_xml": xml_output,
            },
        )
