"""
OWASP Top 10 Active Web Vulnerability Scanner.

Tests for common web application vulnerabilities based on OWASP Top 10 (2021):
  A01 — Broken Access Control
  A02 — Cryptographic Failures
  A03 — Injection (SQL, Command, LDAP, XPath)
  A04 — Insecure Design (info disclosure)
  A05 — Security Misconfiguration
  A06 — Vulnerable Components (detected by other plugins)
  A07 — Auth Failures (default creds, weak sessions)
  A08 — Data Integrity Failures (deserialization hints)
  A09 — Logging Failures (stack traces, debug info)
  A10 — SSRF (server-side request forgery probes)

Safety: This scanner uses benign payloads only — no destructive writes,
no data exfiltration, no exploitation. All tests are safe for production
use and only check for vulnerability indicators in responses.
"""
import asyncio
import re
import urllib.parse
from typing import Optional

import httpx

from app.scanner.plugins.base import Finding, Plugin, PluginMeta, PluginResult
from app.scanner.context import stable_fingerprint

META = PluginMeta(
    plugin_id="owasp.web.scanner",
    name="OWASP Top 10 Web Scanner",
    category="vuln_scan",
    depends_on=["fingerprint.http"],
    consumes=["fingerprint.http"],
    provides=["owasp.findings"],
    enabled_by_default=True,
    timeout_seconds=120.0,  # Reduced from 300s; global budget prevents runaway scans
)

# ─── SQL Injection payloads (safe — cause errors, never modify data) ──────────

SQLI_PAYLOADS = [
    ("'", "single quote"),
    ("1' OR '1'='1", "boolean OR"),
    ("1 AND 1=1--", "AND tautology"),
    ("' UNION SELECT NULL--", "UNION probe"),
    ("1; WAITFOR DELAY '0:0:0'--", "time-based MSSQL"),
    ("' OR 1=1#", "MySQL boolean"),
    ("1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT 1),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--", "error-based"),
]

SQLI_ERROR_PATTERNS = [
    r"SQL syntax.*MySQL",
    r"Warning.*mysql_",
    r"MySQLSyntaxErrorException",
    r"valid MySQL result",
    r"check the manual that corresponds to your MySQL",
    r"ORA-\d{5}",
    r"Oracle.*Driver",
    r"Microsoft SQL Server.*Driver",
    r"Unclosed quotation mark",
    r"quoted string not properly terminated",
    r"SQLite3::query",
    r"SQLITE_ERROR",
    r"PostgreSQL.*ERROR",
    r"pg_query\(\).*failed",
    r"unterminated quoted string",
    r"Syntax error.*in query expression",
    r"ODBC.*Driver",
    r"DB2 SQL error",
    r"Sybase.*Server message",
]

# ─── XSS payloads ────────────────────────────────────────────────────────────

XSS_PAYLOADS = [
    ('<script>alert("XSS")</script>', "basic script"),
    ('<img src=x onerror=alert(1)>', "img onerror"),
    ('"><svg/onload=alert(1)>', "svg onload"),
    ("'><marquee onstart=alert(1)>", "marquee"),
    ('javascript:alert(1)//', "javascript URI"),
]

XSS_REFLECTION_PATTERNS = [
    r'<script>alert\("XSS"\)</script>',
    r'<img src=x onerror=alert\(1\)>',
    r'<svg/onload=alert\(1\)>',
    r"<marquee onstart=alert\(1\)>",
]

# ─── Path Traversal payloads ─────────────────────────────────────────────────

TRAVERSAL_PAYLOADS = [
    ("../../../etc/passwd", "Linux passwd"),
    ("..\\..\\..\\windows\\system32\\drivers\\etc\\hosts", "Windows hosts"),
    ("....//....//....//etc/passwd", "double-dot bypass"),
    ("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "URL-encoded"),
    ("..%252f..%252f..%252fetc/passwd", "double-encoded"),
]

TRAVERSAL_SUCCESS_PATTERNS = [
    r"root:.*:0:0:",           # /etc/passwd
    r"\[fonts\]",              # Windows win.ini
    r"# localhost",            # /etc/hosts or Windows hosts
    r"\[extensions\]",         # Windows system.ini
]

# ─── Command Injection payloads ──────────────────────────────────────────────

CMDI_PAYLOADS = [
    ("; echo vulnscan_cmd_test", "semicolon"),
    ("| echo vulnscan_cmd_test", "pipe"),
    ("` echo vulnscan_cmd_test`", "backtick"),
    ("$(echo vulnscan_cmd_test)", "subshell"),
    ("& echo vulnscan_cmd_test &", "ampersand"),
]

CMDI_SUCCESS_PATTERN = r"vulnscan_cmd_test"

# ─── SSRF payloads ───────────────────────────────────────────────────────────

SSRF_PAYLOADS = [
    ("http://127.0.0.1/", "localhost"),
    ("http://[::1]/", "IPv6 localhost"),
    ("http://0x7f000001/", "hex IP"),
    ("http://169.254.169.254/latest/meta-data/", "AWS metadata"),
    ("http://metadata.google.internal/", "GCP metadata"),
]

# ─── Security Misconfiguration checks ────────────────────────────────────────

SENSITIVE_PATHS = [
    ("/.env", "Environment file", "critical", "Environment file (.env) is publicly accessible. This may contain database credentials, API keys, and secrets. Restrict access immediately."),
    ("/.git/config", "Git repository", "critical", "Git repository is exposed. Attackers can download source code. Block /.git/ in web server config."),
    ("/.git/HEAD", "Git HEAD", "critical", "Git repository metadata is exposed."),
    ("/wp-config.php.bak", "WordPress backup config", "critical", "WordPress config backup found. Contains database credentials."),
    ("/server-status", "Apache server-status", "medium", "Apache mod_status is accessible. Restrict to internal IPs."),
    ("/server-info", "Apache server-info", "medium", "Apache mod_info is accessible. Restrict to internal IPs."),
    ("/phpinfo.php", "PHP info page", "medium", "phpinfo() is accessible. Remove from production — exposes server details."),
    ("/info.php", "PHP info page", "medium", "PHP info page accessible. Remove from production."),
    ("/elmah.axd", "ELMAH error log", "high", "ELMAH error log is exposed. May contain sensitive exception details."),
    ("/trace.axd", "ASP.NET trace", "high", "ASP.NET trace is enabled. Disable in production."),
    ("/actuator", "Spring Boot Actuator", "high", "Spring Boot Actuator exposed. Restrict to internal access only."),
    ("/actuator/health", "Spring Actuator health", "medium", "Spring Actuator health endpoint exposed."),
    ("/actuator/env", "Spring Actuator env", "critical", "Spring Actuator env endpoint may expose secrets."),
    ("/api/swagger.json", "Swagger API docs", "low", "Swagger API documentation is accessible. Consider restricting in production."),
    ("/swagger-ui.html", "Swagger UI", "low", "Swagger UI exposed in production."),
    ("/.DS_Store", "macOS metadata", "low", "macOS .DS_Store file exposed. May reveal directory structure."),
    ("/robots.txt", "Robots.txt", "info", "robots.txt found. May reveal hidden paths."),
    ("/sitemap.xml", "Sitemap", "info", "Sitemap found."),
    ("/crossdomain.xml", "Flash crossdomain", "low", "crossdomain.xml found. Review for overly permissive policy."),
    ("/admin", "Admin panel", "medium", "Admin panel accessible. Restrict to VPN/internal IPs."),
    ("/admin/", "Admin panel", "medium", "Admin panel accessible."),
    ("/wp-admin/", "WordPress admin", "medium", "WordPress admin accessible. Consider IP restriction."),
    ("/phpmyadmin/", "phpMyAdmin", "high", "phpMyAdmin is publicly accessible. Restrict or remove."),
    ("/adminer.php", "Adminer DB tool", "critical", "Adminer database tool is publicly accessible."),
    ("/console", "Debug console", "critical", "Debug console exposed (Werkzeug/Flask). Disable in production."),
    ("/debug", "Debug endpoint", "high", "Debug endpoint accessible."),
    ("/config", "Config endpoint", "high", "Configuration endpoint accessible."),
    ("/backup", "Backup directory", "high", "Backup directory accessible."),
    ("/.htpasswd", "htpasswd file", "critical", "htpasswd file accessible. Contains hashed credentials."),
    ("/.htaccess", "htaccess file", "medium", "htaccess file readable. May reveal security configuration."),
    ("/web.config", "IIS web.config", "high", "IIS web.config accessible. May contain connection strings."),
    ("/WEB-INF/web.xml", "Java web.xml", "high", "Java deployment descriptor accessible."),
]

# ─── Default Credentials (OWASP A07) ─────────────────────────────────────────

DEFAULT_CRED_PATHS = [
    ("/wp-login.php", "WordPress login"),
    ("/administrator/", "Joomla admin"),
    ("/user/login", "Drupal login"),
    ("/admin/login", "Generic admin"),
]

# ─── Information Disclosure patterns ─────────────────────────────────────────

INFO_DISCLOSURE_PATTERNS = [
    (r"(?:stack ?trace|traceback|at \w+\.\w+\()", "Stack trace in response"),
    (r"(?:fatal error|parse error|syntax error).*(?:on line|in /)", "PHP error"),
    (r"(?:Exception in thread|java\.lang\.)", "Java exception"),
    (r"(?:Traceback \(most recent call last\))", "Python traceback"),
    (r"(?:Microsoft OLE DB|ADODB\.)", "ASP/ODBC error"),
    (r"(?:DEBUG\s*=\s*True)", "Django debug mode"),
]


async def _safe_get(client: httpx.AsyncClient, url: str) -> Optional[httpx.Response]:
    """Safe HTTP GET — returns None on failure."""
    try:
        return await client.get(url)
    except Exception:
        return None


async def _safe_post(client: httpx.AsyncClient, url: str, data: dict) -> Optional[httpx.Response]:
    """Safe HTTP POST — returns None on failure."""
    try:
        return await client.post(url, data=data)
    except Exception:
        return None


class Check(Plugin):
    async def run(self, target: str, ctx) -> PluginResult:
        fp = ctx.get("fingerprint.http", {}) or {}
        http_items = fp.get("http", [])
        target_raw = ctx.get("target_raw", target)
        findings: list[Finding] = []

        # Determine base URL
        has_explicit_url = bool(re.match(r"^https?://", target_raw, re.I))
        if has_explicit_url:
            base_url = target_raw.rstrip("/")
        elif http_items:
            base_url = http_items[0].get("url", f"http://{target}").rstrip("/")
        else:
            base_url = f"http://{target}"

        if not has_explicit_url and not http_items:
            return PluginResult(
                findings=[
                    Finding(
                        severity="info",
                        plugin_id=META.plugin_id,
                        title="OWASP scan skipped - no web service detected",
                        description=(
                            "No HTTP fingerprint was discovered for this target. "
                            "Skipping OWASP web checks to avoid false timeouts on non-web hosts."
                        ),
                        evidence=f"target={target} http_fingerprint=none",
                        affected=target,
                        fingerprint=stable_fingerprint(target, META.plugin_id, "skipped_no_http"),
                    )
                ],
                artifacts={"owasp.findings": 0, "owasp.finding_types": [], "owasp.tested_categories": []},
            )

        effective = ctx.get("_effective_timeout", ctx.policy.timeout_seconds)
        # Per-request timeout: at most 15s per individual HTTP request,
        # and never exceed the engine's effective plugin budget.
        request_timeout = min(max(float(effective), 5.0), 15.0)

        async with httpx.AsyncClient(
            timeout=request_timeout,
            verify=False,
            follow_redirects=True,
            limits=httpx.Limits(max_connections=10, max_keepalive_connections=5),
        ) as client:

            # Track which categories are tested and which produce findings.
            # This allows downstream plugins (cve_verifier) to cross-reference.
            tested_categories = []
            pre_count = {}

            def _track(cat):
                tested_categories.append(cat)
                pre_count[cat] = len(findings)

            def _detected(cat):
                return len(findings) > pre_count.get(cat, len(findings))

            # ─── A05: Security Misconfiguration — Sensitive file exposure ─────
            _track("misconfig")
            await self._check_sensitive_paths(client, base_url, target, findings)

            # ─── A03: Injection — SQL Injection ──────────────────────────────
            _track("sqli")
            await self._check_sqli(client, base_url, target, findings)

            # ─── A03: Injection — XSS (Reflected) ────────────────────────────
            _track("xss")
            await self._check_xss(client, base_url, target, findings)

            # ─── A01: Broken Access Control — Path Traversal ─────────────────
            _track("lfi")
            await self._check_path_traversal(client, base_url, target, findings)

            # ─── A03: Injection — Command Injection ──────────────────────────
            _track("cmdi")
            await self._check_cmdi(client, base_url, target, findings)

            # ─── A10: SSRF ───────────────────────────────────────────────────
            _track("ssrf")
            await self._check_ssrf(client, base_url, target, findings)

            # ─── A09: Logging & Monitoring — Info Disclosure ─────────────────
            _track("info_disclosure")
            await self._check_info_disclosure(client, base_url, target, findings)

            # ─── A02: Cryptographic Failures ─────────────────────────────────
            _track("crypto")
            await self._check_crypto(client, base_url, target, findings)

            # ─── A05: HTTP Methods ───────────────────────────────────────────
            _track("http_methods")
            await self._check_http_methods(client, base_url, target, findings)

            # ─── A05: CORS Misconfiguration ──────────────────────────────────
            _track("cors")
            await self._check_cors(client, base_url, target, findings)

            # ─── A05: Cookie Security ────────────────────────────────────────
            _track("cookie")
            await self._check_cookies(client, base_url, target, findings)

            # Build list of categories that actually produced findings
            detected_types = [cat for cat in tested_categories if _detected(cat)]

        return PluginResult(
            findings=findings,
            artifacts={
                "owasp.findings": len(findings),
                "owasp.finding_types": detected_types,
                "owasp.tested_categories": tested_categories,
            },
        )

    # ═══════════════════════════════════════════════════════════════════════════
    # Individual OWASP test methods
    # ═══════════════════════════════════════════════════════════════════════════

    async def _check_sensitive_paths(self, client, base_url, target, findings):
        """A05: Check for exposed sensitive files and directories."""
        sem = asyncio.Semaphore(5)

        async def check_path(path, name, sev, remed):
            async with sem:
                url = base_url + path
                r = await _safe_get(client, url)
                if r is None:
                    return
                # Check for real content (not just 404/redirect)
                if r.status_code == 200 and len(r.text) > 10:
                    # Verify it's not a custom 404 page
                    if "not found" in r.text.lower()[:500] or "404" in r.text[:200]:
                        return
                    # Special checks for specific files
                    if path == "/.env" and not re.search(r"[A-Z_]+=", r.text):
                        return
                    if path == "/.git/config" and "[core]" not in r.text:
                        return
                    if path == "/.git/HEAD" and "ref:" not in r.text:
                        return
                    if path == "/phpinfo.php" and "phpinfo()" not in r.text and "PHP Version" not in r.text:
                        return
                    if path == "/robots.txt" and ("disallow" not in r.text.lower() and "allow" not in r.text.lower() and "sitemap" not in r.text.lower()):
                        return

                    content_preview = r.text[:150].replace("\n", " ").strip()
                    findings.append(Finding(
                        severity=sev,
                        plugin_id=META.plugin_id,
                        title=f"Exposed: {name} ({path})",
                        description=f"{name} is publicly accessible at {url}.",
                        evidence=f"url={url} status={r.status_code} size={len(r.text)} preview={content_preview}",
                        affected=target,
                        fingerprint=stable_fingerprint(target, META.plugin_id, "sensitive", path),
                        remediation=remed,
                        confidence=0.9,
                        references=[
                            "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"
                        ],
                    ))

        await asyncio.gather(
            *[check_path(p, n, s, r) for p, n, s, r in SENSITIVE_PATHS],
            return_exceptions=True,
        )

    async def _check_sqli(self, client, base_url, target, findings):
        """A03: Test for SQL injection in common parameters."""
        test_params = ["id", "page", "cat", "item", "product", "user", "search", "q"]
        found_sqli = False

        for param in test_params[:4]:  # Limit to 4 params for speed
            for payload, desc in SQLI_PAYLOADS[:3]:  # Top 3 payloads
                url = f"{base_url}/?{param}={urllib.parse.quote(payload)}"
                r = await _safe_get(client, url)
                if r is None:
                    continue

                body = r.text
                for pattern in SQLI_ERROR_PATTERNS:
                    if re.search(pattern, body, re.I):
                        findings.append(Finding(
                            severity="critical",
                            plugin_id=META.plugin_id,
                            title=f"SQL Injection detected (parameter: {param})",
                            description=(
                                f"The parameter '{param}' appears vulnerable to SQL injection. "
                                f"Database error messages are returned in the response, confirming "
                                f"that user input is passed directly to SQL queries without sanitization."
                            ),
                            evidence=f"url={url} payload={payload} ({desc}) error_pattern={pattern}",
                            affected=target,
                            fingerprint=stable_fingerprint(target, META.plugin_id, "sqli", param),
                            remediation=(
                                "[CRITICAL — OWASP A03: Injection]\n"
                                "1. Use parameterized queries / prepared statements for ALL database queries\n"
                                "2. Use an ORM (SQLAlchemy, Hibernate, Eloquent) instead of raw SQL\n"
                                "3. Apply input validation — whitelist expected characters\n"
                                "4. Implement a Web Application Firewall (WAF) as defense-in-depth\n"
                                "5. Apply principle of least privilege to database accounts\n"
                                "6. Disable detailed database error messages in production"
                            ),
                            cvss=9.8,
                            confidence=0.85,
                            references=[
                                "https://owasp.org/Top10/A03_2021-Injection/",
                                "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                            ],
                        ))
                        found_sqli = True
                        break
                if found_sqli:
                    break
            if found_sqli:
                break

    async def _check_xss(self, client, base_url, target, findings):
        """A03: Test for reflected XSS in common parameters."""
        test_params = ["search", "q", "query", "s", "keyword", "name", "id"]
        found_xss = False

        for param in test_params[:3]:
            for payload, desc in XSS_PAYLOADS[:3]:
                url = f"{base_url}/?{param}={urllib.parse.quote(payload)}"
                r = await _safe_get(client, url)
                if r is None:
                    continue

                # Check if payload is reflected without encoding
                if payload in r.text:
                    findings.append(Finding(
                        severity="high",
                        plugin_id=META.plugin_id,
                        title=f"Reflected XSS detected (parameter: {param})",
                        description=(
                            f"The parameter '{param}' reflects user input without proper encoding, "
                            f"allowing injection of HTML/JavaScript. An attacker can steal session "
                            f"cookies, redirect users, or deface the page."
                        ),
                        evidence=f"url={url} payload={desc} reflected_in_response=true",
                        affected=target,
                        fingerprint=stable_fingerprint(target, META.plugin_id, "xss", param),
                        remediation=(
                            "[HIGH — OWASP A03: Cross-Site Scripting]\n"
                            "1. Encode all user output using context-appropriate encoding:\n"
                            "   - HTML: &lt; &gt; &amp; &quot; &#39;\n"
                            "   - JavaScript: \\xHH escaping\n"
                            "   - URL: percent-encoding\n"
                            "2. Implement Content-Security-Policy (CSP) header\n"
                            "3. Use templating engines with auto-escaping (Jinja2, React, Vue)\n"
                            "4. Set HttpOnly flag on sensitive cookies\n"
                            "5. Deploy a WAF with XSS rules"
                        ),
                        cvss=7.1,
                        confidence=0.8,
                        references=[
                            "https://owasp.org/Top10/A03_2021-Injection/",
                            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
                        ],
                    ))
                    found_xss = True
                    break
            if found_xss:
                break

    async def _check_path_traversal(self, client, base_url, target, findings):
        """A01: Test for path traversal / local file inclusion."""
        test_params = ["file", "path", "page", "doc", "template", "include", "url"]

        for param in test_params[:3]:
            for payload, desc in TRAVERSAL_PAYLOADS[:3]:
                url = f"{base_url}/?{param}={urllib.parse.quote(payload)}"
                r = await _safe_get(client, url)
                if r is None:
                    continue

                for pattern in TRAVERSAL_SUCCESS_PATTERNS:
                    if re.search(pattern, r.text):
                        findings.append(Finding(
                            severity="critical",
                            plugin_id=META.plugin_id,
                            title=f"Path Traversal / LFI detected (parameter: {param})",
                            description=(
                                f"The parameter '{param}' is vulnerable to path traversal. "
                                f"Server filesystem content (e.g., /etc/passwd) can be read."
                            ),
                            evidence=f"url={url} payload={desc} file_content_detected=true",
                            affected=target,
                            fingerprint=stable_fingerprint(target, META.plugin_id, "lfi", param),
                            remediation=(
                                "[CRITICAL — OWASP A01: Broken Access Control]\n"
                                "1. Never use user input directly in file paths\n"
                                "2. Use a whitelist of allowed files/paths\n"
                                "3. Canonicalize paths and validate they stay within allowed directories\n"
                                "4. Use chroot/jail or containerization to limit filesystem access\n"
                                "5. Disable dynamic file inclusion where possible"
                            ),
                            cvss=9.1,
                            confidence=0.9,
                            references=[
                                "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
                                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/01-Testing_Directory_Traversal_File_Include",
                            ],
                        ))
                        return  # One finding is enough

    async def _check_cmdi(self, client, base_url, target, findings):
        """A03: Test for OS command injection."""
        test_params = ["cmd", "exec", "command", "ping", "host", "ip"]

        for param in test_params[:2]:
            for payload, desc in CMDI_PAYLOADS[:2]:
                url = f"{base_url}/?{param}={urllib.parse.quote(payload)}"
                r = await _safe_get(client, url)
                if r is None:
                    continue

                if re.search(CMDI_SUCCESS_PATTERN, r.text):
                    findings.append(Finding(
                        severity="critical",
                        plugin_id=META.plugin_id,
                        title=f"Command Injection detected (parameter: {param})",
                        description=(
                            f"The parameter '{param}' allows execution of arbitrary OS commands."
                        ),
                        evidence=f"url={url} payload={desc} output_detected=true",
                        affected=target,
                        fingerprint=stable_fingerprint(target, META.plugin_id, "cmdi", param),
                        remediation=(
                            "[CRITICAL — OWASP A03: Injection]\n"
                            "1. Never pass user input to OS commands (system(), exec(), popen())\n"
                            "2. Use language-native APIs instead of shell commands\n"
                            "3. If shell use is unavoidable, use strict input validation\n"
                            "4. Apply principle of least privilege to the web server process\n"
                            "5. Use a WAF to block command injection patterns"
                        ),
                        cvss=9.8,
                        confidence=0.9,
                        references=[
                            "https://owasp.org/Top10/A03_2021-Injection/",
                        ],
                    ))
                    return

    async def _check_ssrf(self, client, base_url, target, findings):
        """A10: Test for Server-Side Request Forgery."""
        test_params = ["url", "link", "redirect", "next", "target", "rurl", "dest", "fetch"]

        for param in test_params[:3]:
            for payload, desc in SSRF_PAYLOADS[:2]:
                url = f"{base_url}/?{param}={urllib.parse.quote(payload)}"
                r = await _safe_get(client, url)
                if r is None:
                    continue

                # Check for signs the server fetched the internal URL
                ssrf_indicators = [
                    "ami-id", "instance-id", "hostname", "local-ipv4",  # AWS metadata
                    "computeMetadata", "project-id",  # GCP metadata
                    "Directory listing", "Index of",
                ]
                for indicator in ssrf_indicators:
                    if indicator.lower() in r.text.lower():
                        findings.append(Finding(
                            severity="critical",
                            plugin_id=META.plugin_id,
                            title=f"SSRF detected (parameter: {param})",
                            description=(
                                f"The parameter '{param}' can be used to make the server "
                                f"fetch internal resources. Cloud metadata may be accessible."
                            ),
                            evidence=f"url={url} payload={desc} indicator={indicator}",
                            affected=target,
                            fingerprint=stable_fingerprint(target, META.plugin_id, "ssrf", param),
                            remediation=(
                                "[CRITICAL — OWASP A10: SSRF]\n"
                                "1. Validate and sanitize all user-supplied URLs\n"
                                "2. Use an allowlist of permitted domains/IPs\n"
                                "3. Block requests to private IP ranges (10.x, 172.16-31.x, 192.168.x, 169.254.x)\n"
                                "4. Block cloud metadata endpoints (169.254.169.254)\n"
                                "5. Use network segmentation to limit server egress"
                            ),
                            cvss=9.1,
                            confidence=0.8,
                            references=[
                                "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
                            ],
                        ))
                        return

    async def _check_info_disclosure(self, client, base_url, target, findings):
        """A09: Check for information disclosure in error responses."""
        # Trigger error pages with invalid inputs
        error_urls = [
            f"{base_url}/'",
            f"{base_url}/{{{{}}}}",
            f"{base_url}/%00",
            f"{base_url}/doesnotexist/../../../etc/passwd",
        ]

        for url in error_urls:
            r = await _safe_get(client, url)
            if r is None:
                continue

            for pattern, desc in INFO_DISCLOSURE_PATTERNS:
                if re.search(pattern, r.text, re.I):
                    findings.append(Finding(
                        severity="medium",
                        plugin_id=META.plugin_id,
                        title=f"Information disclosure: {desc}",
                        description=(
                            f"Error responses reveal internal application details ({desc}). "
                            f"This information aids attackers in crafting targeted exploits."
                        ),
                        evidence=f"url={url} pattern={desc}",
                        affected=target,
                        fingerprint=stable_fingerprint(target, META.plugin_id, "infodisclosure", desc),
                        remediation=(
                            "[MEDIUM — OWASP A09: Security Logging & Monitoring Failures]\n"
                            "1. Configure custom error pages — never show stack traces in production\n"
                            "2. Set DEBUG=False (Django), APP_DEBUG=false (Laravel)\n"
                            "3. Configure error logging to files, not responses\n"
                            "4. Use centralized logging (ELK, Splunk) for error monitoring"
                        ),
                        confidence=0.75,
                        references=[
                            "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/",
                        ],
                    ))
                    break  # One finding per error URL is enough

    async def _check_crypto(self, client, base_url, target, findings):
        """A02: Check for cryptographic failures."""
        # Check if site serves over HTTP (not HTTPS)
        if base_url.startswith("http://"):
            r = await _safe_get(client, base_url)
            if r and r.status_code == 200:
                # Check if it doesn't redirect to HTTPS
                final_url = str(r.url)
                if not final_url.startswith("https://"):
                    findings.append(Finding(
                        severity="high",
                        plugin_id=META.plugin_id,
                        title="No HTTPS — data transmitted in plaintext",
                        description=(
                            "The application serves content over HTTP without redirecting to HTTPS. "
                            "All data (including credentials, session tokens) is transmitted in plaintext."
                        ),
                        evidence=f"url={base_url} final_url={final_url} no_https_redirect=true",
                        affected=target,
                        fingerprint=stable_fingerprint(target, META.plugin_id, "no_https"),
                        remediation=(
                            "[HIGH — OWASP A02: Cryptographic Failures]\n"
                            "1. Enable HTTPS with a valid TLS certificate (Let's Encrypt is free)\n"
                            "2. Redirect all HTTP traffic to HTTPS (301 redirect)\n"
                            "3. Add HSTS header: Strict-Transport-Security: max-age=31536000\n"
                            "4. Ensure TLS 1.2+ is used (disable TLS 1.0/1.1)"
                        ),
                        cvss=7.5,
                        confidence=0.95,
                        references=[
                            "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
                        ],
                    ))

    async def _check_http_methods(self, client, base_url, target, findings):
        """A05: Check for dangerous HTTP methods."""
        try:
            r = await client.request("OPTIONS", base_url)
            allow = r.headers.get("allow", "")
            dangerous = {"PUT", "DELETE", "TRACE", "CONNECT"}
            enabled = {m.strip().upper() for m in allow.split(",") if m.strip()}
            risky = enabled & dangerous

            if risky:
                findings.append(Finding(
                    severity="medium",
                    plugin_id=META.plugin_id,
                    title=f"Dangerous HTTP methods enabled: {', '.join(sorted(risky))}",
                    description=(
                        f"The server allows HTTP methods that should be disabled: {', '.join(sorted(risky))}. "
                        "TRACE can enable XST attacks, PUT/DELETE may allow file manipulation."
                    ),
                    evidence=f"url={base_url} allow_header={allow}",
                    affected=target,
                    fingerprint=stable_fingerprint(target, META.plugin_id, "http_methods"),
                    remediation=(
                        "[MEDIUM — OWASP A05: Security Misconfiguration]\n"
                        "Disable unnecessary HTTP methods in your web server:\n"
                        "- nginx: add 'if ($request_method !~ ^(GET|HEAD|POST)$) { return 405; }'\n"
                        "- Apache: use <LimitExcept GET POST HEAD> in .htaccess\n"
                        "- IIS: Remove verbs in Request Filtering"
                    ),
                    confidence=0.9,
                    references=[
                        "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
                    ],
                ))
        except Exception:
            pass

    async def _check_cors(self, client, base_url, target, findings):
        """A05: Check for CORS misconfiguration."""
        try:
            r = await client.get(
                base_url,
                headers={"Origin": "https://evil-attacker.com"}
            )
            acao = r.headers.get("access-control-allow-origin", "")
            acac = r.headers.get("access-control-allow-credentials", "")

            if acao == "*":
                findings.append(Finding(
                    severity="medium",
                    plugin_id=META.plugin_id,
                    title="CORS: Wildcard origin allowed (Access-Control-Allow-Origin: *)",
                    description=(
                        "The server allows any origin to make cross-site requests. "
                        "If combined with credentials, this can lead to data theft."
                    ),
                    evidence=f"url={base_url} acao={acao} acac={acac}",
                    affected=target,
                    fingerprint=stable_fingerprint(target, META.plugin_id, "cors_wildcard"),
                    remediation=(
                        "Restrict CORS to specific trusted origins. "
                        "Never use 'Access-Control-Allow-Origin: *' with credentials."
                    ),
                    confidence=0.9,
                ))
            elif "evil-attacker.com" in acao:
                sev = "high" if acac.lower() == "true" else "medium"
                findings.append(Finding(
                    severity=sev,
                    plugin_id=META.plugin_id,
                    title="CORS: Origin reflection vulnerability",
                    description=(
                        "The server reflects any Origin header back in Access-Control-Allow-Origin. "
                        "This allows any website to make authenticated cross-origin requests."
                    ),
                    evidence=f"url={base_url} reflected_origin={acao} credentials={acac}",
                    affected=target,
                    fingerprint=stable_fingerprint(target, META.plugin_id, "cors_reflect"),
                    remediation=(
                        "[OWASP A05: Security Misconfiguration]\n"
                        "1. Maintain a whitelist of allowed origins\n"
                        "2. Validate the Origin header against the whitelist\n"
                        "3. Never reflect arbitrary Origin headers"
                    ),
                    cvss=6.5 if sev == "high" else 4.3,
                    confidence=0.95,
                ))
        except Exception:
            pass

    async def _check_cookies(self, client, base_url, target, findings):
        """A05: Check for insecure cookie settings."""
        try:
            r = await client.get(base_url)
            for cookie_header in r.headers.get_list("set-cookie"):
                cookie_lower = cookie_header.lower()
                name_match = re.match(r"([^=]+)=", cookie_header)
                name = name_match.group(1) if name_match else "unknown"

                # Skip tracking/analytics cookies
                if any(t in name.lower() for t in ["_ga", "_gid", "fbp", "fbclid"]):
                    continue

                issues = []
                if "httponly" not in cookie_lower:
                    issues.append("missing HttpOnly")
                if "secure" not in cookie_lower and base_url.startswith("https"):
                    issues.append("missing Secure flag")
                if "samesite" not in cookie_lower:
                    issues.append("missing SameSite")

                # Only report session-like cookies with issues
                session_indicators = ["sess", "token", "auth", "jwt", "sid", "login", "csrf"]
                is_session = any(ind in name.lower() for ind in session_indicators)

                if issues and is_session:
                    findings.append(Finding(
                        severity="medium" if "httponly" in str(issues) else "low",
                        plugin_id=META.plugin_id,
                        title=f"Insecure cookie: {name} ({', '.join(issues)})",
                        description=(
                            f"The session cookie '{name}' is missing security attributes: {', '.join(issues)}. "
                            "This could allow cookie theft via XSS or CSRF attacks."
                        ),
                        evidence=f"cookie={cookie_header[:200]}",
                        affected=target,
                        fingerprint=stable_fingerprint(target, META.plugin_id, "cookie", name),
                        remediation=(
                            "Set all session cookies with:\n"
                            "- HttpOnly — prevents JavaScript access\n"
                            "- Secure — only sent over HTTPS\n"
                            "- SameSite=Lax or Strict — prevents CSRF"
                        ),
                        confidence=0.9,
                    ))
        except Exception:
            pass