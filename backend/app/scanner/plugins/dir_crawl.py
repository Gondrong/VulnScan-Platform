"""
Directory Crawling & Discovery — finds hidden directories, files,
and endpoints via wordlist brute-force and HTML link spidering.

Two modes:
  1. Wordlist scan — checks common paths (admin panels, backups, configs)
  2. Spider crawl — follows HTML links to discover pages and map the app

OWASP relevance:
  A01 — Broken Access Control (finding hidden admin pages)
  A05 — Security Misconfiguration (exposed backup/config files)
"""
import asyncio
import re
from urllib.parse import urljoin, urlparse

import httpx

from app.scanner.plugins.base import Plugin, PluginMeta, PluginResult, Finding
from app.scanner.context import stable_fingerprint

META = PluginMeta(
    plugin_id="recon.directory.crawl",
    name="Directory Crawling & Discovery",
    category="recon",
    depends_on=["fingerprint.http"],
    consumes=["fingerprint.http"],
    provides=["recon.directories"],
    enabled_by_default=True,
    timeout_seconds=60.0,
)

# ── Wordlist: common directories and files ────────────────────────────────────
# Sorted by severity/importance
WORDLIST = [
    # Critical: Sensitive config/data exposure
    (".env", "critical", "Environment file with secrets"),
    (".env.bak", "critical", "Environment file backup"),
    (".env.local", "critical", "Local environment file"),
    (".env.production", "critical", "Production secrets"),
    (".git/config", "critical", "Git repository exposed"),
    (".svn/entries", "high", "SVN repository exposed"),
    (".hg/store", "high", "Mercurial repository exposed"),
    ("wp-config.php.bak", "critical", "WordPress config backup"),
    ("wp-config.php~", "critical", "WordPress config editor backup"),
    ("config.php.bak", "critical", "PHP config backup"),
    ("web.config.bak", "high", "IIS config backup"),
    (".htpasswd", "critical", "Apache htpasswd file"),
    (".htaccess.bak", "high", "htaccess backup"),
    ("id_rsa", "critical", "SSH private key"),
    (".ssh/id_rsa", "critical", "SSH private key"),
    ("server.key", "critical", "TLS private key"),
    ("dump.sql", "critical", "Database dump"),
    ("backup.sql", "critical", "Database backup"),
    ("db.sql", "critical", "Database export"),
    ("database.sql", "critical", "Database export"),

    # High: Admin panels and management
    ("admin", "medium", "Admin panel"),
    ("admin/", "medium", "Admin panel"),
    ("administrator", "medium", "Admin panel"),
    ("wp-admin/", "medium", "WordPress admin"),
    ("wp-login.php", "medium", "WordPress login"),
    ("phpmyadmin/", "high", "phpMyAdmin database manager"),
    ("phpmyadmin", "high", "phpMyAdmin"),
    ("pma/", "high", "phpMyAdmin shortcut"),
    ("adminer.php", "high", "Adminer database manager"),
    ("manager/html", "high", "Tomcat Manager"),
    ("manager/status", "high", "Tomcat Status"),
    ("jmx-console/", "high", "JBoss JMX Console"),
    ("web-console/", "high", "JBoss Web Console"),
    ("admin-console/", "high", "Admin Console"),
    ("cpanel", "medium", "cPanel"),
    ("plesk", "medium", "Plesk Panel"),
    ("webmail", "medium", "Webmail interface"),

    # Medium: Debug/info endpoints
    ("phpinfo.php", "medium", "PHP information page"),
    ("info.php", "medium", "PHP info"),
    ("test.php", "medium", "Test script"),
    ("debug", "medium", "Debug endpoint"),
    ("debug/", "medium", "Debug directory"),
    ("console", "high", "Debug console (Werkzeug)"),
    ("trace.axd", "high", "ASP.NET trace"),
    ("elmah.axd", "high", "ELMAH error log"),
    ("server-status", "medium", "Apache server status"),
    ("server-info", "medium", "Apache server info"),
    ("nginx-status", "medium", "Nginx status"),
    ("stub_status", "medium", "Nginx stub status"),
    ("actuator", "high", "Spring Boot Actuator"),
    ("actuator/env", "critical", "Spring Actuator env (secrets)"),
    ("actuator/health", "low", "Spring Actuator health"),
    ("actuator/metrics", "medium", "Spring Actuator metrics"),
    ("actuator/beans", "medium", "Spring Actuator beans"),
    ("metrics", "low", "Application metrics"),
    ("health", "info", "Health endpoint"),
    ("healthz", "info", "Health check"),
    ("status", "info", "Status endpoint"),

    # API discovery
    ("api", "info", "API root"),
    ("api/v1", "info", "API v1"),
    ("api/v2", "info", "API v2"),
    ("graphql", "medium", "GraphQL endpoint"),
    ("graphiql", "medium", "GraphiQL IDE"),
    ("swagger.json", "low", "Swagger spec"),
    ("swagger-ui.html", "low", "Swagger UI"),
    ("api-docs", "low", "API documentation"),
    ("openapi.json", "low", "OpenAPI spec"),
    ("docs", "info", "Documentation"),
    ("redoc", "low", "ReDoc API docs"),

    # Backup/archive files
    ("backup/", "high", "Backup directory"),
    ("backups/", "high", "Backups directory"),
    ("bak/", "high", "Backup directory"),
    ("old/", "medium", "Old files directory"),
    ("temp/", "medium", "Temporary directory"),
    ("tmp/", "medium", "Temporary directory"),
    ("archive/", "medium", "Archive directory"),
    ("upload/", "medium", "Upload directory"),
    ("uploads/", "medium", "Uploads directory"),
    ("files/", "low", "Files directory"),

    # Common CMS paths
    ("wp-content/", "info", "WordPress content"),
    ("wp-includes/", "info", "WordPress includes"),
    ("wp-json/wp/v2/users", "medium", "WordPress user enumeration"),
    ("xmlrpc.php", "medium", "WordPress XML-RPC (brute-force vector)"),
    ("sites/default/files/", "info", "Drupal files"),
    ("user/register", "low", "Drupal user registration"),
    ("components/com_admin/", "info", "Joomla components"),

    # Version control & CI
    (".gitignore", "low", "Git ignore file"),
    (".dockerignore", "low", "Docker ignore file"),
    ("Dockerfile", "medium", "Dockerfile exposed"),
    ("docker-compose.yml", "high", "Docker Compose file"),
    ("docker-compose.yaml", "high", "Docker Compose file"),
    (".gitlab-ci.yml", "high", "GitLab CI config"),
    (".github/workflows", "medium", "GitHub Actions"),
    ("Jenkinsfile", "medium", "Jenkins pipeline"),
    ("Makefile", "low", "Makefile"),
    ("package.json", "low", "Node.js dependencies"),
    ("composer.json", "low", "PHP dependencies"),
    ("requirements.txt", "low", "Python dependencies"),
    ("Gemfile", "low", "Ruby dependencies"),

    # Common directories
    ("cgi-bin/", "low", "CGI-bin directory"),
    ("icons/", "info", "Icons directory"),
    ("images/", "info", "Images directory"),
    ("img/", "info", "Images directory"),
    ("css/", "info", "CSS directory"),
    ("js/", "info", "JavaScript directory"),
    ("static/", "info", "Static files"),
    ("assets/", "info", "Assets directory"),
    ("media/", "info", "Media directory"),
    ("logs/", "high", "Log directory"),
    ("log/", "high", "Log directory"),
    ("error.log", "high", "Error log file"),
    ("access.log", "high", "Access log file"),

    # Miscellaneous
    ("robots.txt", "info", "Robots.txt"),
    ("sitemap.xml", "info", "Sitemap"),
    ("crossdomain.xml", "low", "Flash cross-domain policy"),
    ("clientaccesspolicy.xml", "low", "Silverlight cross-domain policy"),
    ("security.txt", "info", "Security contact info"),
    (".well-known/security.txt", "info", "Security.txt (RFC 9116)"),
    ("favicon.ico", "info", "Favicon"),
    ("humans.txt", "info", "Humans.txt"),
    (".DS_Store", "low", "macOS directory metadata"),
    ("Thumbs.db", "low", "Windows thumbnail cache"),
    ("desktop.ini", "low", "Windows desktop config"),
]

# Response patterns that indicate a real page (not custom 404)
FALSE_POSITIVE_PATTERNS = [
    r"(?:page|file)?\s*not\s*found",
    r"404\s*(error|not found)",
    r"does not exist",
    r"no such file",
    r"cannot be found",
    r"the page you requested",
]


async def _check_path(
    client: httpx.AsyncClient,
    base_url: str,
    path: str,
    sem: asyncio.Semaphore,
    baseline_len: int | None,
) -> dict | None:
    """Check if a path exists. Returns dict with details or None."""
    async with sem:
        url = f"{base_url}/{path}"
        try:
            r = await client.get(url)
        except Exception:
            return None

        if r.status_code in (404, 410, 501):
            return None
        if r.status_code in (401, 403):
            # Protected but exists
            return {"path": path, "status": r.status_code, "size": 0, "protected": True}
        if r.status_code in (200, 301, 302, 307, 308):
            body = r.text[:1000]
            # Check for custom 404 pages
            for pat in FALSE_POSITIVE_PATTERNS:
                if re.search(pat, body, re.I):
                    return None
            # Check for baseline similarity (soft 404)
            if baseline_len and abs(len(r.text) - baseline_len) < 50:
                return None
            # Real hit
            return {
                "path": path,
                "status": r.status_code,
                "size": len(r.text),
                "protected": False,
            }
        return None


async def _spider(client: httpx.AsyncClient, base_url: str, max_pages: int = 30) -> set:
    """Simple HTML link spider — follows links to discover pages."""
    visited = set()
    queue = [base_url]
    domain = urlparse(base_url).netloc
    discovered = set()

    while queue and len(visited) < max_pages:
        url = queue.pop(0)
        if url in visited:
            continue
        visited.add(url)

        try:
            r = await client.get(url)
            if r.status_code != 200:
                continue
            if "text/html" not in r.headers.get("content-type", ""):
                continue

            # Extract links
            links = re.findall(r'(?:href|src|action)=["\']([^"\']+)["\']', r.text, re.I)
            for link in links:
                full = urljoin(url, link)
                parsed = urlparse(full)
                if parsed.netloc != domain:
                    continue
                clean = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                if clean not in visited:
                    queue.append(clean)
                    path = parsed.path.lstrip("/")
                    if path:
                        discovered.add(path)
        except Exception:
            continue

    return discovered


class Check(Plugin):
    async def run(self, target: str, ctx) -> PluginResult:
        fp = ctx.get("fingerprint.http", {}) or {}
        http_items = fp.get("http", [])
        target_raw = ctx.get("target_raw", target)
        findings = []

        has_explicit_url = bool(re.match(r"^https?://", target_raw, re.I))

        # Skip if no web service detected (like OWASP scanner does)
        if not has_explicit_url and not http_items:
            return PluginResult(
                findings=[
                    Finding(
                        severity="info",
                        plugin_id=META.plugin_id,
                        title="Directory crawl skipped — no web service detected",
                        description=(
                            "No HTTP fingerprint was discovered for this target. "
                            "Skipping directory crawl to avoid wasting time on non-web hosts."
                        ),
                        evidence=f"target={target} http_fingerprint=none",
                        affected=target,
                        fingerprint=stable_fingerprint(target, META.plugin_id, "skipped_no_http"),
                    )
                ],
                artifacts={"recon.directories": []},
            )

        # Determine base URL
        if has_explicit_url:
            base_url = target_raw.rstrip("/")
        elif http_items:
            base_url = http_items[0].get("url", f"http://{target}").rstrip("/")
        else:
            base_url = f"http://{target}"

        effective = ctx.get("_effective_timeout", 60.0)
        req_timeout = min(8.0, effective * 0.1)  # 10% of budget per request

        async with httpx.AsyncClient(
            timeout=req_timeout,
            verify=False,
            follow_redirects=True,
            limits=httpx.Limits(max_connections=10, max_keepalive_connections=5),
        ) as client:

            # Get baseline for soft 404 detection
            baseline_len = None
            try:
                baseline = await client.get(f"{base_url}/thispageshouldnotexist_xyzzy_404")
                if baseline.status_code == 200:
                    baseline_len = len(baseline.text)
            except Exception:
                pass

            # ── Phase 1: Wordlist brute-force ────────────────────────────────
            sem = asyncio.Semaphore(8)
            results = await asyncio.gather(
                *[_check_path(client, base_url, path, sem, baseline_len)
                  for path, _, _ in WORDLIST],
                return_exceptions=True,
            )

            discovered = []
            for (path, severity, desc), result in zip(WORDLIST, results):
                if isinstance(result, dict) and result is not None:
                    discovered.append({
                        "path": path,
                        "severity": severity,
                        "description": desc,
                        "status": result["status"],
                        "size": result["size"],
                        "protected": result.get("protected", False),
                    })

            # Generate findings from discovered paths
            for d in discovered:
                path = d["path"]
                sev = d["severity"]
                # Downgrade severity for protected (401/403) resources
                if d["protected"]:
                    sev = "info"
                    desc = f"{d['description']} (access denied — but path exists)"
                else:
                    desc = d["description"]

                # Skip info-level directory listings that are common/expected
                if sev == "info" and d["status"] == 200 and d["size"] < 50:
                    continue

                findings.append(Finding(
                    severity=sev,
                    plugin_id=META.plugin_id,
                    title=f"Discovered: /{path} — {desc}",
                    description=(
                        f"Directory crawl found /{path} (HTTP {d['status']}, "
                        f"{d['size']} bytes{', protected' if d['protected'] else ''}). "
                        f"{desc}."
                    ),
                    evidence=f"url={base_url}/{path} status={d['status']} size={d['size']} protected={d['protected']}",
                    affected=target,
                    fingerprint=stable_fingerprint(target, META.plugin_id, path),
                    remediation=_remediation(path, sev),
                    confidence=0.85 if not d["protected"] else 0.7,
                    references=[
                        "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
                        "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
                    ],
                ))

            # ── Phase 2: HTML Spider ──────────────────────────────────────────
            try:
                spidered = await _spider(client, base_url, max_pages=20)
                if spidered:
                    findings.append(Finding(
                        severity="info",
                        plugin_id=META.plugin_id,
                        title=f"Spider crawl: {len(spidered)} paths discovered",
                        description=f"HTML link spider discovered {len(spidered)} unique paths on the target.",
                        evidence=f"crawled_paths={sorted(list(spidered))[:50]}",
                        affected=target,
                        fingerprint=stable_fingerprint(target, META.plugin_id, "spider"),
                    ))
            except Exception:
                pass

        # Summary finding
        crit_high = sum(1 for d in discovered if d["severity"] in ("critical", "high") and not d["protected"])
        findings.append(Finding(
            severity="info",
            plugin_id=META.plugin_id,
            title=f"Directory scan: {len(discovered)} paths found ({crit_high} critical/high)",
            evidence=f"wordlist_size={len(WORDLIST)} discovered={len(discovered)} critical_high={crit_high}",
            affected=target,
            fingerprint=stable_fingerprint(target, META.plugin_id, "summary"),
        ))

        return PluginResult(
            findings=findings,
            artifacts={"recon.directories": [d["path"] for d in discovered]},
        )


def _remediation(path: str, severity: str) -> str:
    """Generate remediation advice based on path type."""
    if ".env" in path or ".git" in path or ".svn" in path:
        return (
            "Block access to sensitive files in your web server:\n"
            "  Nginx: location ~ /\\. { deny all; }\n"
            "  Apache: <FilesMatch \"^\\.\"> Require all denied </FilesMatch>\n"
            "Remove development files from production servers."
        )
    if "admin" in path.lower() or "manager" in path.lower() or "console" in path.lower():
        return (
            "Restrict admin panel access:\n"
            "  - Use IP-based restrictions (allow only VPN/office IPs)\n"
            "  - Implement strong authentication (2FA)\n"
            "  - Change default admin URL to a non-guessable path\n"
            "  - Use a WAF to block brute-force attempts"
        )
    if "backup" in path.lower() or ".bak" in path or ".sql" in path:
        return (
            "Remove backup files from web-accessible directories.\n"
            "Store backups in a secure, non-public location.\n"
            "Block access to common backup extensions in web server config."
        )
    if "phpinfo" in path or "info.php" in path or "test.php" in path:
        return "Remove debug/info scripts from production. phpinfo() exposes server configuration details."
    if "actuator" in path:
        return (
            "Restrict Spring Boot Actuator endpoints:\n"
            "  management.endpoints.web.exposure.include=health,info\n"
            "  Require authentication for all actuator endpoints."
        )
    if "log" in path.lower():
        return "Block access to log files. Move logs outside web root or restrict via web server config."
    return f"Review if /{path} should be publicly accessible. Remove or restrict as needed."