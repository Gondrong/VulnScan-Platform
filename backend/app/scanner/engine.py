import asyncio
import ipaddress
import json
import re
import urllib.parse

from app.core.config import settings
from app.scanner.context import ScanContext, ScanPolicy, stable_fingerprint
from app.scanner.plugins.base import Finding
from app.scanner.plugins.loader import load_plugins, topo_sort

PLUGINS = load_plugins()  # returns dict[str, Plugin]
ORDER = topo_sort(PLUGINS)  # returns list[str] of plugin_ids


def _parse_target(raw: str) -> tuple[str, str]:
    """
    Parse target into (host, scheme).
    Returns the actual hostname/IP and the detected scheme.
    """
    raw = raw.strip()
    scheme = "unknown"

    # If it starts with a scheme, parse as URL
    if re.match(r"^https?://", raw, re.I):
        parsed = urllib.parse.urlparse(raw)
        scheme = parsed.scheme.lower()
        host = parsed.hostname or ""
        return host, scheme

    parts = raw.split("/", 1)
    base = parts[0]

    if ":" in base:
        if base.startswith("["):
            host = base.split("]")[0].lstrip("[")
        else:
            host = base.split(":")[0]
    else:
        host = base

    return host, scheme


def _allowlisted(target: str, scan_type: str = "internal") -> bool:
    """
    Returns True if the target is allowed to be scanned.

    For EXTERNAL scans: always allowed — the allowlist is for internal
    network boundaries, not for restricting public web scans.

    For INTERNAL scans: checks against ALLOWLIST env var (CIDRs and domain suffixes).
    If ALLOWLIST is empty, '*', or not set, ALL targets are allowed.
    """
    # External scans bypass the internal allowlist
    if scan_type == "external":
        return True

    raw_allowlist = (settings.ALLOWLIST or "").strip()

    if not raw_allowlist or raw_allowlist == "*":
        return True

    allow_entries = [x.strip() for x in raw_allowlist.split(",") if x.strip()]

    if not allow_entries:
        return True

    host, _ = _parse_target(target)
    if not host:
        return False

    # Try to match as IP address first
    try:
        ip = ipaddress.ip_address(host)
        for entry in allow_entries:
            if "/" in entry:
                try:
                    network = ipaddress.ip_network(entry, strict=False)
                    if ip in network:
                        return True
                except ValueError:
                    pass
            else:
                try:
                    if ip == ipaddress.ip_address(entry):
                        return True
                except ValueError:
                    pass
        return False
    except ValueError:
        pass

    # Match as domain
    host_lower = host.lower().rstrip(".")
    for entry in allow_entries:
        entry = entry.lower()
        if entry.startswith("."):
            if host_lower == entry.lstrip(".") or host_lower.endswith(entry):
                return True
        else:
            if host_lower == entry:
                return True

    return False


def _enabled(selection_json: str) -> list[str]:
    try:
        sel = json.loads(selection_json or "{}")
    except Exception:
        sel = {}

    if not sel:
        enabled = {
            pid
            for pid, chk in PLUGINS.items()
            if chk.meta.enabled_by_default
        }
    else:
        enabled = {
            pid for pid, v in sel.items() if v and pid in PLUGINS
        }

    # Resolve dependencies
    changed = True
    while changed:
        changed = False
        for pid in list(enabled):
            if pid not in PLUGINS:
                continue
            for dep in PLUGINS[pid].meta.depends_on:
                if dep in PLUGINS and dep not in enabled:
                    enabled.add(dep)
                    changed = True

    return [pid for pid in ORDER if pid in enabled]


# ─── Remediation Knowledge Base ────────────────────────────────────────────────

_REMEDIATION_DB = {
    "nginx": {
        "remediation": "Upgrade nginx to the latest stable version. Visit https://nginx.org/en/download.html for the latest release. Apply security patches and harden configuration by removing unnecessary modules, setting 'server_tokens off', and configuring proper TLS settings.",
        "category": "web_server",
    },
    "apache": {
        "remediation": "Upgrade Apache HTTP Server to the latest version from https://httpd.apache.org/download.cgi. Disable unnecessary modules (a2dismod), set 'ServerTokens Prod' and 'ServerSignature Off', enforce TLS 1.2+, and configure security headers.",
        "category": "web_server",
    },
    "http_server": {
        "remediation": "Upgrade Apache HTTP Server to the latest version. Disable server version disclosure in headers, enforce HTTPS, and apply all available security patches.",
        "category": "web_server",
    },
    "openssh": {
        "remediation": "Upgrade OpenSSH to the latest version via your package manager (apt upgrade openssh-server / yum update openssh-server). Disable root login (PermitRootLogin no), use key-based authentication only, disable SSHv1, and restrict allowed ciphers/MACs to modern algorithms.",
        "category": "remote_access",
    },
    "redis": {
        "remediation": "Upgrade Redis to the latest stable version from https://redis.io/download. Bind to localhost only (bind 127.0.0.1), enable AUTH with a strong password, disable dangerous commands (rename-command FLUSHALL ''), and run Redis as non-root.",
        "category": "database",
    },
    "elasticsearch": {
        "remediation": "Upgrade Elasticsearch to the latest version. Enable X-Pack security, configure TLS for transport and HTTP layers, set up authentication, and restrict network access to trusted hosts only.",
        "category": "database",
    },
    "postgresql": {
        "remediation": "Upgrade PostgreSQL to the latest minor version. Review pg_hba.conf to restrict access, enforce SSL connections, use strong passwords, and disable trust authentication.",
        "category": "database",
    },
    "mysql": {
        "remediation": "Upgrade MySQL to the latest version. Run mysql_secure_installation, disable remote root login, enforce SSL, and remove anonymous users.",
        "category": "database",
    },
    "wordpress": {
        "remediation": "Update WordPress core, all themes, and all plugins to the latest versions. Remove unused themes/plugins, enforce strong admin passwords, enable two-factor authentication, and use a Web Application Firewall (WAF).",
        "category": "cms",
    },
    "drupal": {
        "remediation": "Update Drupal core and all contributed modules to the latest versions. Review security advisories at https://www.drupal.org/security. Restrict admin access and configure proper file permissions.",
        "category": "cms",
    },
    "joomla": {
        "remediation": "Update Joomla to the latest version and patch all extensions. Review Joomla security advisories, enforce strong admin passwords, and restrict backend access by IP.",
        "category": "cms",
    },
    "magento": {
        "remediation": "Apply all Adobe Commerce / Magento security patches. Update to the latest version, enable two-factor admin authentication, review third-party extensions for vulnerabilities.",
        "category": "cms",
    },
    "openssl": {
        "remediation": "Upgrade OpenSSL to the latest version via your package manager. Disable TLS 1.0/1.1, prefer TLS 1.3, use strong cipher suites, and rotate certificates if a key compromise vulnerability was involved.",
        "category": "crypto",
    },
    "laravel": {
        "remediation": "Update Laravel to the latest LTS or stable version. Run 'composer update' to update dependencies, ensure APP_DEBUG=false in production, and rotate APP_KEY if compromised.",
        "category": "framework",
    },
    "nextjs": {
        "remediation": "Update Next.js to the latest version with 'npm update next'. Review and update all npm dependencies, and ensure no sensitive data is exposed in client-side bundles.",
        "category": "framework",
    },
    "php": {
        "remediation": "Upgrade PHP to the latest supported version (check https://www.php.net/supported-versions.php). Disable dangerous functions (exec, system, passthru) in php.ini, set expose_php=Off, and enable security extensions.",
        "category": "runtime",
    },
    "python": {
        "remediation": "Upgrade Python to the latest patch release of your major version. Review dependencies with 'pip audit' or 'safety check' and update vulnerable packages.",
        "category": "runtime",
    },
    "nodejs": {
        "remediation": "Upgrade Node.js to the latest LTS version from https://nodejs.org/. Run 'npm audit fix' to patch known dependency vulnerabilities.",
        "category": "runtime",
    },
    "sudo": {
        "remediation": "Upgrade sudo to the latest version. Review /etc/sudoers for overly permissive rules, enforce password prompts, and limit sudo access to required users only.",
        "category": "system",
    },
    "bash": {
        "remediation": "Upgrade bash to the latest version via your package manager. Ensure Shellshock (CVE-2014-6271) and related patches are applied.",
        "category": "system",
    },
    "glibc": {
        "remediation": "Upgrade glibc (libc6) to the latest version. This requires a system restart. Schedule maintenance and apply with 'apt upgrade libc6' or equivalent.",
        "category": "system",
    },
    "linux_kernel": {
        "remediation": "Update the Linux kernel to the latest patched version for your distribution. Reboot to activate the new kernel. Consider enabling automatic security updates.",
        "category": "system",
    },
    "curl": {
        "remediation": "Upgrade curl and libcurl to the latest version. Verify with 'curl --version'. If using curl in scripts, ensure TLS verification is not disabled.",
        "category": "networking",
    },
    "git": {
        "remediation": "Upgrade git to the latest version. Review repository permissions and ensure .git directories are not exposed on web servers.",
        "category": "development",
    },
    "docker": {
        "remediation": "Update Docker Engine to the latest version. Run containers as non-root, enable content trust, scan images for vulnerabilities, and keep base images updated.",
        "category": "container",
    },
    "containerd": {
        "remediation": "Upgrade containerd to the latest version. Review runtime security settings and ensure proper namespace isolation.",
        "category": "container",
    },
    "iis": {
        "remediation": "Apply the latest Windows security updates for IIS. Disable directory browsing, remove unnecessary ISAPI extensions, configure request filtering, and enforce TLS 1.2+.",
        "category": "web_server",
    },
    "asp.net": {
        "remediation": "Update the .NET runtime to the latest version. Disable detailed error messages in production (customErrors mode='On'), enforce HTTPS, and review web.config security settings.",
        "category": "framework",
    },
    "tomcat": {
        "remediation": "Upgrade Apache Tomcat to the latest version. Remove default applications (manager, examples), disable AJP if unused, configure HTTPS, and set secure cookie flags.",
        "category": "web_server",
    },
    "react": {
        "remediation": "Update React and related dependencies to the latest versions. Run 'npm audit' to identify and fix known vulnerabilities in the dependency tree.",
        "category": "framework",
    },
    "vue": {
        "remediation": "Update Vue.js and related packages to the latest versions. Review for XSS risks in v-html usage and ensure proper input sanitization.",
        "category": "framework",
    },
    "jquery": {
        "remediation": "Update jQuery to the latest version (3.x+). Older versions have known XSS vulnerabilities. Review usage of .html() and similar methods for XSS risks.",
        "category": "library",
    },
}

_SEVERITY_REMEDIATION = {
    "critical": "This is a CRITICAL severity vulnerability that requires immediate remediation within 7 days per SLA policy. Prioritize patching, apply vendor-provided fixes, and consider temporary mitigations (WAF rules, network segmentation, disabling affected features) while permanent fixes are deployed.",
    "high": "This is a HIGH severity vulnerability that should be remediated within 14 days per SLA policy. Apply available patches, review vendor advisories, and implement compensating controls if immediate patching is not feasible.",
    "medium": "This is a MEDIUM severity vulnerability with a 30-day remediation SLA. Plan patching during the next maintenance window. Review if compensating controls are already in place.",
    "low": "This is a LOW severity vulnerability with a 60-day remediation SLA. Address during regular patching cycles. Document any accepted risk if remediation is deferred.",
    "info": "Informational finding. Review and address as part of security hardening efforts.",
}


def _enrich_finding_remediation(finding: Finding) -> Finding:
    """Enrich a finding with remediation steps and version/target details.
    Info-severity findings (compliance passes) are skipped.
    SLA POLICY text is added by the worker after final severity calc.
    """
    if finding.severity and finding.severity.lower() == "info":
        return finding

    if finding.remediation and len(finding.remediation) > 50:
        return finding

    remediation_parts = []
    evidence_lower = (finding.evidence or "").lower()
    title_lower = (finding.title or "").lower()
    plugin_lower = (finding.plugin_id or "").lower()
    combined = f"{evidence_lower} {title_lower} {plugin_lower}"

    for product_key, info in _REMEDIATION_DB.items():
        if product_key in combined:
            remediation_parts.append(f"[REMEDIATION] {info['remediation']}")
            break

    # Extract version info from evidence
    version_match = re.search(
        r'(?:version|installed|ver)[=: ]*([0-9][0-9.]+[0-9a-zA-Z.-]*)',
        finding.evidence or "", re.I
    )
    if version_match:
        ver = version_match.group(1)
        remediation_parts.append(
            f"[AFFECTED VERSION] Detected version: {ver}. "
            f"Check the vendor's security advisory for this specific version "
            f"and upgrade to the latest patched release."
        )

    # Extract CPE info for component details
    cpe_match = re.search(r'cpe[=: ]*(cpe:2\.3:[^ ]+)', finding.evidence or "", re.I)
    if cpe_match:
        cpe = cpe_match.group(1)
        cpe_parts = cpe.split(":")
        if len(cpe_parts) >= 6:
            vendor = cpe_parts[3].replace("_", " ").title()
            product = cpe_parts[4].replace("_", " ").title()
            version = cpe_parts[5] if len(cpe_parts) > 5 and cpe_parts[5] != "*" else "unknown"
            remediation_parts.append(
                f"[AFFECTED COMPONENT] {vendor} {product} version {version}. "
                f"Search for security advisories at the vendor's website."
            )

    # CVE-specific remediation
    if finding.cve and finding.cve.startswith("CVE-"):
        remediation_parts.append(
            f"[CVE REFERENCE] {finding.cve} — "
            f"Review full details at https://nvd.nist.gov/vuln/detail/{finding.cve} "
            f"and https://www.cve.org/CVERecord?id={finding.cve}. "
            f"Check if your vendor has released a specific patch for this CVE."
        )

    if finding.is_kev:
        remediation_parts.append(
            "[CISA KEV] This vulnerability is actively exploited in the wild. "
            "Immediate remediation is required per CISA BOD 22-01. "
            "Apply patches within the KEV due date or implement "
            "compensating controls immediately."
        )

    # SLA POLICY is added by the worker after final severity calc

    if not remediation_parts:
        remediation_parts.append(
            "[GENERAL] Review the finding evidence and apply vendor-recommended "
            "patches or configuration changes. Consult the relevant security "
            "advisory for specific remediation steps."
        )

    finding.remediation = "\n\n".join(remediation_parts)
    return finding


def _enrich_finding_description(finding: Finding, target: str, scan_type: str) -> Finding:
    """Enrich finding description with target/version context if sparse."""
    desc_parts = []

    if finding.description:
        desc_parts.append(finding.description)

    if target and target not in (finding.description or ""):
        desc_parts.append(f"Target: {target} (scan type: {scan_type})")

    evidence = finding.evidence or ""
    versions = re.findall(
        r'(?:version|installed|ver)[=: ]*([0-9][0-9.]+[0-9a-zA-Z.-]*)',
        evidence, re.I
    )
    if versions and not any(v in (finding.description or "") for v in versions):
        desc_parts.append(f"Detected version(s): {', '.join(set(versions))}")

    ports = re.findall(r'open_ports=\[([^\]]+)\]', evidence)
    if ports and "port" not in (finding.description or "").lower():
        desc_parts.append(f"Open ports: {ports[0]}")

    pkg_match = re.search(r'package=(\S+)\s+installed=(\S+)', evidence)
    if pkg_match:
        pkg, ver = pkg_match.group(1), pkg_match.group(2)
        if pkg not in (finding.description or ""):
            desc_parts.append(f"Affected package: {pkg} (installed version: {ver})")

    finding.description = "\n".join(desc_parts) if desc_parts else finding.description
    return finding


async def scan_target(
    target: str, profile: dict, workspace_id: int, scan_type: str = "internal"
) -> list[Finding]:
    """
    Main scan entry point.
    Returns a list of Finding objects (not dicts).
    """
    # Allowlist check — external scans bypass the internal allowlist
    if not _allowlisted(target, scan_type):
        return [
            Finding(
                severity="info",
                plugin_id="policy.allowlist",
                title="Target blocked by allowlist policy",
                description=(
                    f"Target '{target}' is not in the configured allowlist. "
                    f"Add it to the ALLOWLIST environment variable to permit scanning. "
                    f"Alternatively, use 'External / Web' scan type for public targets."
                ),
                remediation=(
                    "To scan this target, either:\n"
                    "1. Switch to 'External / Web' scan type for public targets\n"
                    "2. Add the target to the ALLOWLIST in Settings or .env file\n"
                    "   Example: ALLOWLIST=10.0.0.0/8,.example.com,target.com"
                ),
                evidence=f"ALLOWLIST={settings.ALLOWLIST}",
                affected=target,
                fingerprint=stable_fingerprint(target, "allowlist"),
            )
        ]

    # Resolve actual host for context
    host, scheme = _parse_target(target)

    policy = ScanPolicy(timeout_seconds=float(settings.SCAN_TIMEOUT_SECONDS))
    ctx = ScanContext(policy=policy)
    ctx.set("workspace_id", workspace_id)
    ctx.set("target_raw", target)
    ctx.set("target_host", host)
    ctx.set("target_scheme", scheme)
    ctx.set("scan_type", scan_type)

    try:
        options = json.loads(profile.get("options_json", "{}") or "{}")
    except Exception:
        options = {}
    ctx.set("profile_options", options)

    findings_out: list[Finding] = []
    enabled = _enabled(profile.get("plugin_selection_json", "{}"))

    for pid in enabled:
        chk = PLUGINS[pid]
        # External scans get extra timeout for network latency
        effective_timeout = chk.meta.timeout_seconds
        if scan_type == "external":
            effective_timeout = max(effective_timeout * 2.5, 25.0)
        try:
            res = await asyncio.wait_for(
                chk.run(host, ctx),
                timeout=effective_timeout + 2,
            )
        except asyncio.TimeoutError:
            findings_out.append(
                Finding(
                    severity="info",
                    plugin_id=pid,
                    title=f"Plugin timed out: {chk.meta.name}",
                    evidence=f"timeout={chk.meta.timeout_seconds}s",
                    affected=target,
                    fingerprint=stable_fingerprint(target, pid, "timeout"),
                    remediation="The plugin exceeded its timeout. This may indicate network latency or a heavily filtered target. Try increasing SCAN_TIMEOUT_SECONDS in .env.",
                )
            )
            continue
        except Exception as exc:
            findings_out.append(
                Finding(
                    severity="info",
                    plugin_id=pid,
                    title=f"Plugin error: {chk.meta.name}",
                    evidence=str(exc)[:512],
                    affected=target,
                    fingerprint=stable_fingerprint(target, pid, "error"),
                    remediation=f"The {chk.meta.name} plugin encountered an error. Check target connectivity and plugin configuration.",
                )
            )
            continue

        # Merge artifacts
        for k, v in (res.artifacts or {}).items():
            ctx.set(k, v)

        for f in res.findings or []:
            if not f.fingerprint:
                f.fingerprint = stable_fingerprint(target, f.plugin_id, f.title)
            if not ctx.dedup(f.fingerprint):
                continue
            findings_out.append(f)

    # Enrich all findings with remediation and description details
    for f in findings_out:
        _enrich_finding_remediation(f)
        _enrich_finding_description(f, target, scan_type)

    return findings_out