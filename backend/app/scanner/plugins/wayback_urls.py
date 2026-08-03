"""
Wayback Machine URL Discovery Plugin
Queries the Wayback Machine CDX API to discover historical URLs for the target
domain, identifying potentially sensitive paths such as admin panels, API
endpoints, configuration files, login pages, and backup files.

No external tool dependencies — uses httpx for HTTP requests.
"""
import logging
import re
import urllib.parse

import httpx

from app.scanner.plugins.base import Finding, Plugin, PluginMeta, PluginResult
from app.scanner.context import stable_fingerprint

logger = logging.getLogger("vulnscan.plugin.wayback_urls")

META = PluginMeta(
    plugin_id="recon.wayback_urls",
    name="Wayback Machine URL Discovery",
    category="recon",
    depends_on=["fingerprint.http"],
    provides=["recon.wayback_urls"],
    enabled_by_default=True,
    timeout_seconds=30.0,
)

# CDX API endpoint
_CDX_API = (
    "http://web.archive.org/cdx/search/cdx"
    "?url=*.{domain}/*&output=json&collapse=urlkey&limit=500&fl=original"
)

# Patterns that indicate potentially sensitive paths
_SENSITIVE_PATTERNS: list[tuple[str, str]] = [
    (r"/\.env", ".env file"),
    (r"/\.git", ".git directory"),
    (r"/\.svn", ".svn directory"),
    (r"/\.htaccess", ".htaccess file"),
    (r"/\.htpasswd", ".htpasswd file"),
    (r"/\.aws", "AWS config"),
    (r"/\.docker", "Docker config"),
    (r"/wp-config\.php", "WordPress config"),
    (r"/config\.(php|json|yml|yaml|xml|js|ini|toml)", "configuration file"),
    (r"/admin", "admin panel"),
    (r"/administrator", "administrator panel"),
    (r"/manager", "manager panel"),
    (r"/dashboard", "dashboard"),
    (r"/phpmyadmin", "phpMyAdmin"),
    (r"/backup", "backup file/directory"),
    (r"/\.bak$", "backup file"),
    (r"\.sql$", "SQL dump"),
    (r"\.tar\.gz$", "compressed archive"),
    (r"\.zip$", "ZIP archive"),
    (r"/api/", "API endpoint"),
    (r"/graphql", "GraphQL endpoint"),
    (r"/swagger", "Swagger/OpenAPI docs"),
    (r"/api-docs", "API documentation"),
    (r"/login", "login page"),
    (r"/signin", "sign-in page"),
    (r"/register", "registration page"),
    (r"/debug", "debug endpoint"),
    (r"/actuator", "Spring Actuator"),
    (r"/console", "console interface"),
    (r"/shell", "shell interface"),
    (r"/test", "test endpoint"),
    (r"/staging", "staging path"),
    (r"/internal", "internal path"),
    (r"/private", "private path"),
    (r"/secret", "secret path"),
    (r"/credentials", "credentials path"),
    (r"/token", "token endpoint"),
    (r"/xmlrpc", "XML-RPC endpoint"),
    (r"/cgi-bin", "CGI directory"),
    (r"/server-status", "server status"),
    (r"/server-info", "server info"),
]

# Patterns for "interesting" (but not necessarily sensitive) URLs
_INTERESTING_PATTERNS: list[tuple[str, str]] = [
    (r"/api/v[0-9]", "versioned API endpoint"),
    (r"/rest/", "REST endpoint"),
    (r"/oauth", "OAuth endpoint"),
    (r"/sso", "SSO endpoint"),
    (r"/upload", "upload endpoint"),
    (r"/export", "export endpoint"),
    (r"/download", "download endpoint"),
    (r"/webhook", "webhook endpoint"),
    (r"/callback", "callback endpoint"),
    (r"/wp-json", "WordPress JSON API"),
    (r"/wp-admin", "WordPress admin"),
    (r"/wp-content/plugins", "WordPress plugin"),
    (r"/sitemap\.xml", "sitemap"),
    (r"/robots\.txt", "robots.txt"),
    (r"/crossdomain\.xml", "crossdomain policy"),
]


def _extract_domain(target: str, target_raw: str) -> str:
    """Extract the base domain from target."""
    raw = target_raw or target
    if re.match(r"^https?://", raw, re.I):
        parsed = urllib.parse.urlparse(raw)
        host = parsed.hostname or target
    else:
        host = target

    host = host.split(":")[0].strip().lower()

    # Skip IP addresses
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", host):
        return ""

    parts = host.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host


class Check(Plugin):
    async def run(self, target: str, ctx) -> PluginResult:
        target_raw = ctx.get("target_raw", target)
        findings: list[Finding] = []
        discovered_urls: list[str] = []

        domain = _extract_domain(target, target_raw)
        if not domain:
            return PluginResult(artifacts={"recon.wayback_urls": []})

        # Query Wayback Machine CDX API
        url = _CDX_API.format(domain=urllib.parse.quote(domain))
        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(25.0),
                follow_redirects=True,
                headers={"User-Agent": "VulnScan/2.1"},
            ) as client:
                resp = await client.get(url)
                resp.raise_for_status()
                data = resp.json()
        except Exception as e:
            logger.debug("Wayback CDX query failed for %s: %s", domain, e)
            findings.append(Finding(
                severity="info",
                plugin_id=META.plugin_id,
                title=f"Wayback Machine query failed for {domain}",
                evidence=f"error={str(e)[:200]}",
                affected=target,
                fingerprint=stable_fingerprint(target, META.plugin_id, "error"),
                remediation=(
                    "Wayback Machine CDX API query failed. This may be due to "
                    "network restrictions, rate limiting, or the domain having "
                    "no archived snapshots."
                ),
            ))
            return PluginResult(
                findings=findings,
                artifacts={"recon.wayback_urls": []},
            )

        if not data or not isinstance(data, list):
            return PluginResult(artifacts={"recon.wayback_urls": []})

        # First row is headers in CDX JSON output, skip it
        raw_urls: list[str] = []
        for row in data:
            if isinstance(row, list) and len(row) >= 1:
                u = row[0]
                if isinstance(u, str) and u.startswith("http"):
                    raw_urls.append(u)

        # De-duplicate URLs
        seen: set[str] = set()
        unique_urls: list[str] = []
        for u in raw_urls:
            normalised = u.split("?")[0].rstrip("/").lower()
            if normalised not in seen:
                seen.add(normalised)
                unique_urls.append(u)

        discovered_urls = unique_urls

        if not discovered_urls:
            findings.append(Finding(
                severity="info",
                plugin_id=META.plugin_id,
                title=f"No archived URLs found for {domain}",
                evidence=f"domain={domain}",
                affected=target,
                fingerprint=stable_fingerprint(target, META.plugin_id, "empty"),
            ))
            return PluginResult(
                findings=findings,
                artifacts={"recon.wayback_urls": []},
            )

        # Summary finding for all discovered URLs
        fp = stable_fingerprint(target, META.plugin_id, "summary", str(len(discovered_urls)))
        findings.append(Finding(
            severity="info",
            plugin_id=META.plugin_id,
            title=f"Wayback Machine: {len(discovered_urls)} unique URL(s) for {domain}",
            description=(
                f"The Wayback Machine contains {len(discovered_urls)} unique archived URLs "
                f"for {domain}. Historical URLs may reveal deprecated endpoints, removed pages, "
                f"and previously exposed resources."
            ),
            evidence=(
                f"domain={domain} total_urls={len(discovered_urls)} "
                f"sample={discovered_urls[:10]}"
            ),
            affected=target,
            fingerprint=fp,
            confidence=0.95,
            remediation=(
                f"[INFO] {len(discovered_urls)} historical URLs discovered via Wayback Machine\n\n"
                f"[ACTION]\n"
                f"1. Review archived URLs for previously exposed sensitive content\n"
                f"2. Check if any deprecated endpoints are still accessible\n"
                f"3. Look for removed pages that may have contained sensitive information\n"
                f"4. Verify that old API endpoints have been properly decommissioned"
            ),
            references=["https://web.archive.org/"],
        ))

        # Classify URLs — sensitive paths
        sensitive_found: list[tuple[str, str]] = []
        for u in discovered_urls:
            path_lower = urllib.parse.urlparse(u).path.lower()
            for pattern, label in _SENSITIVE_PATTERNS:
                if re.search(pattern, path_lower, re.I):
                    sensitive_found.append((u, label))
                    break  # one match per URL is enough

        if sensitive_found:
            sample_evidence = "; ".join(
                f"{label}: {u}" for u, label in sensitive_found[:15]
            )
            fp_sens = stable_fingerprint(
                target, META.plugin_id, "sensitive", str(len(sensitive_found))
            )
            findings.append(Finding(
                severity="medium",
                plugin_id=META.plugin_id,
                title=(
                    f"Potentially sensitive paths found in Wayback archives for {domain}"
                ),
                description=(
                    f"{len(sensitive_found)} URL(s) in the Wayback Machine archives point to "
                    f"potentially sensitive resources such as admin panels, configuration files, "
                    f"backup archives, or API endpoints. Even if these have been removed, cached "
                    f"versions may still contain sensitive data."
                ),
                evidence=f"domain={domain} sensitive_count={len(sensitive_found)} paths=[{sample_evidence}]",
                affected=target,
                fingerprint=fp_sens,
                confidence=0.75,
                remediation=(
                    "[OWASP A01:2021 Broken Access Control]\n"
                    "Sensitive paths were discovered in archived web content.\n\n"
                    "[ACTION]\n"
                    "1. Verify that sensitive paths are no longer publicly accessible\n"
                    "2. Request removal of cached copies from the Wayback Machine "
                    "if they contain secrets (https://web.archive.org/web/removals)\n"
                    "3. Rotate any credentials that may have been exposed\n"
                    "4. Block sensitive paths in web server configuration\n"
                    "5. Add sensitive directories to robots.txt (but do not rely "
                    "on robots.txt alone for security)\n\n"
                    "[SENSITIVE PATHS FOUND]\n"
                    + "\n".join(f"  - [{label}] {u}" for u, label in sensitive_found[:20])
                ),
                references=[
                    "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
                    "https://web.archive.org/",
                ],
            ))

        # Classify URLs — interesting (info-level) paths
        interesting_found: list[tuple[str, str]] = []
        for u in discovered_urls:
            path_lower = urllib.parse.urlparse(u).path.lower()
            # Skip if already flagged as sensitive
            if any(u == su for su, _ in sensitive_found):
                continue
            for pattern, label in _INTERESTING_PATTERNS:
                if re.search(pattern, path_lower, re.I):
                    interesting_found.append((u, label))
                    break

        if interesting_found:
            fp_int = stable_fingerprint(
                target, META.plugin_id, "interesting", str(len(interesting_found))
            )
            findings.append(Finding(
                severity="info",
                plugin_id=META.plugin_id,
                title=f"Interesting endpoints in Wayback archives for {domain}",
                description=(
                    f"{len(interesting_found)} archived URL(s) point to API endpoints, "
                    f"authentication flows, or other notable resources that may warrant "
                    f"further investigation."
                ),
                evidence=(
                    f"domain={domain} count={len(interesting_found)} "
                    f"paths={[u for u, _ in interesting_found[:10]]}"
                ),
                affected=target,
                fingerprint=fp_int,
                confidence=0.70,
                remediation=(
                    "Review the following archived endpoints for potential exposure:\n"
                    + "\n".join(f"  - [{label}] {u}" for u, label in interesting_found[:20])
                ),
                references=["https://web.archive.org/"],
            ))

        return PluginResult(
            findings=findings,
            artifacts={"recon.wayback_urls": discovered_urls},
        )
