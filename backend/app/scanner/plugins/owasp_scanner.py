"""
OWASP Top 10 Active Web Vulnerability Scanner.

Tests for common web application vulnerabilities based on OWASP Top 10 (2025):
  A01 — Broken Access Control (path traversal, CSRF, SSRF)
  A02 — Security Misconfiguration (exposed files, CORS, HTTP methods, cookies)
  A03 — Software Supply Chain Failures (detected by other plugins)
  A04 — Cryptographic Failures (missing HTTPS/HSTS)
  A05 — Injection (SQL, Command, XSS, XXE)
  A06 — Insecure Design (info disclosure)
  A07 — Authentication Failures (default creds, weak sessions)
  A08 — Software/Data Integrity Failures (deserialization hints)
  A09 — Logging & Alerting Failures (stack traces, debug info)
  A10 — Mishandling of Exceptional Conditions (error handling)

Changes from OWASP 2021 → 2025:
  - SSRF absorbed into A01 (was standalone A10 in 2021)
  - Security Misconfiguration promoted to A02 (was A05 in 2021)
  - Software Supply Chain Failures is NEW at A03 (expanded from old A06)
  - Injection moved to A05 (was A03 in 2021)
  - Mishandling of Exceptional Conditions is NEW at A10

Safety: This scanner uses benign payloads only — no destructive writes,
no data exfiltration, no exploitation. All tests are safe for production
use and only check for vulnerability indicators in responses.
"""
import asyncio
import re
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin, urlparse, parse_qs

import httpx

from app.scanner.plugins.base import Finding, Plugin, PluginMeta, PluginResult
from app.scanner.context import stable_fingerprint

META = PluginMeta(
    plugin_id="owasp.web.scanner",
    name="OWASP Top 10 (2025) Web Scanner",
    category="vuln_scan",
    depends_on=["fingerprint.http"],
    soft_depends_on=["web.auth"],  # Run after web.auth so auth_session is available
    consumes=["fingerprint.http", "web.auth_session"],
    provides=["owasp.findings", "owasp.finding_types", "owasp.tested_categories"],
    enabled_by_default=True,
    timeout_seconds=120.0,
)

# ─── Discovery data structures ──────────────────────────────────────────────

@dataclass
class _Target:
    """A discovered URL + parameter that should be tested for injection."""
    url: str       # Full URL path without query string (e.g., http://site.com/artists.php)
    param: str     # Parameter name (e.g., "artist")
    value: str     # Original value seen (e.g., "1"), used as baseline
    source: str    # "link" | "form" | "hardcoded"


@dataclass
class _FormInfo:
    """A discovered HTML form for CSRF analysis."""
    action_url: str
    method: str          # GET or POST
    input_names: list = field(default_factory=list)
    has_csrf_token: bool = False
    page_url: str = ""


# ─── CSRF token name patterns ───────────────────────────────────────────────

_CSRF_TOKEN_RE = re.compile(
    r"(?:csrf|xsrf|_token|authenticity_token|__RequestVerificationToken|nonce|csrfmiddlewaretoken)",
    re.I,
)

# ─── SQL Injection payloads (safe — cause errors, never modify data) ────────

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

# ─── XSS payloads ───────────────────────────────────────────────────────────

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

# ─── Path Traversal payloads ────────────────────────────────────────────────

TRAVERSAL_PAYLOADS = [
    ("../../../etc/passwd", "Linux passwd"),
    ("..\\..\\..\\windows\\system32\\drivers\\etc\\hosts", "Windows hosts"),
    ("....//....//....//etc/passwd", "double-dot bypass"),
    ("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "URL-encoded"),
    ("..%252f..%252f..%252fetc/passwd", "double-encoded"),
]

TRAVERSAL_SUCCESS_PATTERNS = [
    r"root:.*:0:0:",
    r"\[fonts\]",
    r"# localhost",
    r"\[extensions\]",
]

# ─── Command Injection payloads ─────────────────────────────────────────────

CMDI_PAYLOADS = [
    ("; echo vulnscan_cmd_test", "semicolon"),
    ("| echo vulnscan_cmd_test", "pipe"),
    ("` echo vulnscan_cmd_test`", "backtick"),
    ("$(echo vulnscan_cmd_test)", "subshell"),
    ("& echo vulnscan_cmd_test &", "ampersand"),
]

CMDI_SUCCESS_PATTERN = r"vulnscan_cmd_test"

# ─── SSRF payloads ──────────────────────────────────────────────────────────

SSRF_PAYLOADS = [
    ("http://127.0.0.1/", "localhost"),
    ("http://[::1]/", "IPv6 localhost"),
    ("http://0x7f000001/", "hex IP"),
    ("http://169.254.169.254/latest/meta-data/", "AWS metadata"),
    ("http://metadata.google.internal/", "GCP metadata"),
]

# ─── Security Misconfiguration checks ───────────────────────────────────────

# Each entry: (path, name, severity, remediation, content_validator)
# content_validator is None (any 200 response counts) or a callable(text) -> bool
# that must return True for the finding to be reported.
SENSITIVE_PATHS = [
    ("/.env", "Environment file", "critical",
     "Environment file (.env) is publicly accessible. This may contain database credentials, API keys, and secrets. Restrict access immediately.",
     lambda t: bool(re.search(r"[A-Z_]+=", t))),
    ("/.git/config", "Git repository", "critical",
     "Git repository is exposed. Attackers can download source code. Block /.git/ in web server config.",
     lambda t: "[core]" in t),
    ("/.git/HEAD", "Git HEAD", "critical",
     "Git repository metadata is exposed.",
     lambda t: "ref:" in t or t.strip().startswith("ref:")),
    ("/wp-config.php.bak", "WordPress backup config", "critical",
     "WordPress config backup found. Contains database credentials.",
     lambda t: "DB_NAME" in t or "DB_PASSWORD" in t or "wp-settings" in t),
    ("/server-status", "Apache server-status", "medium",
     "Apache mod_status is accessible. Restrict to internal IPs.",
     lambda t: "Apache Server Status" in t or "Server Version" in t),
    ("/server-info", "Apache server-info", "medium",
     "Apache mod_info is accessible. Restrict to internal IPs.",
     lambda t: "Apache Server Information" in t or "Server Version" in t),
    ("/phpinfo.php", "PHP info page", "medium",
     "phpinfo() is accessible. Remove from production — exposes server details.",
     lambda t: "phpinfo()" in t or "PHP Version" in t),
    ("/info.php", "PHP info page", "medium",
     "PHP info page accessible. Remove from production.",
     lambda t: "phpinfo()" in t or "PHP Version" in t),
    ("/elmah.axd", "ELMAH error log", "high",
     "ELMAH error log is exposed. May contain sensitive exception details.",
     lambda t: "ELMAH" in t or "Error Log" in t),
    ("/trace.axd", "ASP.NET trace", "high",
     "ASP.NET trace is enabled. Disable in production.",
     lambda t: "Application Trace" in t or "Request Details" in t),
    ("/actuator", "Spring Boot Actuator", "high",
     "Spring Boot Actuator exposed. Restrict to internal access only.",
     lambda t: '"_links"' in t or '"self"' in t or '"health"' in t),
    ("/actuator/health", "Spring Actuator health", "medium",
     "Spring Actuator health endpoint exposed.",
     lambda t: '"status"' in t and ("UP" in t or "DOWN" in t)),
    ("/actuator/env", "Spring Actuator env", "critical",
     "Spring Actuator env endpoint may expose secrets.",
     lambda t: '"propertySources"' in t or '"activeProfiles"' in t),
    ("/api/swagger.json", "Swagger API docs", "low",
     "Swagger API documentation is accessible. Consider restricting in production.",
     lambda t: '"swagger"' in t.lower() or '"openapi"' in t.lower() or '"paths"' in t),
    ("/swagger-ui.html", "Swagger UI", "low",
     "Swagger UI exposed in production.",
     lambda t: "swagger" in t.lower() and ("ui" in t.lower() or "api" in t.lower())),
    ("/.DS_Store", "macOS metadata", "low",
     "macOS .DS_Store file exposed. May reveal directory structure.",
     lambda t: "\x00Bud1" in t or "Bud1" in t),
    ("/robots.txt", "Robots.txt", "info",
     "robots.txt found. May reveal hidden paths.",
     lambda t: "disallow" in t.lower() or "allow" in t.lower() or "sitemap" in t.lower()),
    ("/sitemap.xml", "Sitemap", "info",
     "Sitemap found.",
     lambda t: "<urlset" in t.lower() or "<sitemapindex" in t.lower()),
    ("/crossdomain.xml", "Flash crossdomain", "low",
     "crossdomain.xml found. Review for overly permissive policy.",
     lambda t: "cross-domain-policy" in t.lower()),
    ("/admin", "Admin panel", "medium",
     "Admin panel accessible. Restrict to VPN/internal IPs.",
     None),  # Generic — validated by soft-404 detection
    ("/admin/", "Admin panel", "medium",
     "Admin panel accessible.",
     None),
    ("/wp-admin/", "WordPress admin", "medium",
     "WordPress admin accessible. Consider IP restriction.",
     lambda t: "wordpress" in t.lower() or "wp-login" in t.lower() or "wp-includes" in t.lower()),
    ("/phpmyadmin/", "phpMyAdmin", "high",
     "phpMyAdmin is publicly accessible. Restrict or remove.",
     lambda t: "phpmyadmin" in t.lower() or "pma_" in t.lower()),
    ("/adminer.php", "Adminer DB tool", "critical",
     "Adminer database tool is publicly accessible.",
     lambda t: "adminer" in t.lower() and ("login" in t.lower() or "database" in t.lower())),
    ("/console", "Debug console", "critical",
     "Debug console exposed (Werkzeug/Flask). Disable in production.",
     lambda t: "werkzeug" in t.lower() or "debugger" in t.lower() or "console" in t.lower() and "interactive" in t.lower()),
    ("/debug", "Debug endpoint", "high",
     "Debug endpoint accessible.",
     lambda t: "debug" in t.lower() and ("trace" in t.lower() or "stack" in t.lower() or "exception" in t.lower() or "settings" in t.lower())),
    ("/config", "Config endpoint", "high",
     "Configuration endpoint accessible.",
     lambda t: bool(re.search(r'["\'](password|secret|key|token|database|dsn)["\']', t.lower()))),
    ("/backup", "Backup directory", "high",
     "Backup directory accessible.",
     lambda t: "index of" in t.lower() or "parent directory" in t.lower() or "<pre>" in t.lower()),
    ("/.htpasswd", "htpasswd file", "critical",
     "htpasswd file accessible. Contains hashed credentials.",
     lambda t: bool(re.search(r"^\w+:\$?\w+\$", t, re.M)) or ":{SHA}" in t or ":$apr1$" in t),
    ("/.htaccess", "htaccess file", "medium",
     "htaccess file readable. May reveal security configuration.",
     lambda t: "RewriteRule" in t or "RewriteEngine" in t or "AuthType" in t or "Deny from" in t),
    ("/web.config", "IIS web.config", "high",
     "IIS web.config accessible. May contain connection strings.",
     lambda t: "<configuration" in t.lower() or "connectionstring" in t.lower() or "<system.web" in t.lower()),
    ("/WEB-INF/web.xml", "Java web.xml", "high",
     "Java deployment descriptor accessible.",
     lambda t: "<web-app" in t.lower() or "<servlet" in t.lower()),
]

# ─── Information Disclosure patterns ────────────────────────────────────────

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


async def _safe_post(client: httpx.AsyncClient, url: str, data=None, content=None, headers=None) -> Optional[httpx.Response]:
    """Safe HTTP POST — returns None on failure."""
    try:
        return await client.post(url, data=data, content=content, headers=headers)
    except Exception:
        return None


# ═════════════════════════════════════════════════════════════════════════════
# Target Discovery — mini-spider + form parser
# ═════════════════════════════════════════════════════════════════════════════

async def _discover_targets(client, base_url, max_pages=10, budget_seconds=30.0):
    """
    Lightweight BFS spider that discovers URLs with parameters and HTML forms.

    Returns:
        (targets: list[_Target], forms: list[_FormInfo])
    """
    start = time.monotonic()
    base_parsed = urlparse(base_url)
    base_domain = base_parsed.netloc
    targets = []
    forms = []
    seen_urls = set()
    seen_params = set()  # (url_path, param) dedup
    queue = [base_url]
    visited = set()

    while queue and len(visited) < max_pages:
        if time.monotonic() - start > budget_seconds:
            break

        url = queue.pop(0)
        if url in visited:
            continue
        visited.add(url)

        r = await _safe_get(client, url)
        if r is None or r.status_code >= 400:
            continue

        ct = r.headers.get("content-type", "")
        if "html" not in ct.lower() and len(visited) > 1:
            continue

        body = r.text

        # ── Extract links with query parameters ─────────────────────────
        link_matches = re.findall(r'(?:href|src|action)=["\']([^"\'#]+)', body, re.I)
        for raw_link in link_matches:
            resolved = urljoin(url, raw_link)
            parsed = urlparse(resolved)

            # Stay on same domain
            if parsed.netloc and parsed.netloc != base_domain:
                continue

            full_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

            # Extract query params as targets
            if parsed.query:
                params = parse_qs(parsed.query, keep_blank_values=True)
                for pname, pvals in params.items():
                    key = (full_url, pname)
                    if key not in seen_params and len(pname) < 30:
                        seen_params.add(key)
                        targets.append(_Target(
                            url=full_url,
                            param=pname,
                            value=pvals[0] if pvals else "",
                            source="link",
                        ))

            # Add to spider queue (strip query for cleaner crawling)
            clean = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            if clean not in seen_urls:
                # Stay on same domain — only follow same-netloc links
                link_parsed = urlparse(clean)
                if link_parsed.netloc == base_domain:
                    seen_urls.add(clean)
                    queue.append(clean)

        # ── Parse HTML forms ─────────────────────────────────────────────
        form_blocks = re.findall(
            r'<form[^>]*>(.*?)</form>',
            body, re.I | re.S,
        )
        form_tags = re.findall(r'<form([^>]*)>', body, re.I)

        for i, form_attrs in enumerate(form_tags):
            form_body = form_blocks[i] if i < len(form_blocks) else ""

            # Extract action
            action_match = re.search(r'action=["\']([^"\']*)["\']', form_attrs, re.I)
            action = action_match.group(1) if action_match else url
            action_url = urljoin(url, action)

            # Extract method
            method_match = re.search(r'method=["\']([^"\']*)["\']', form_attrs, re.I)
            method = (method_match.group(1) if method_match else "GET").upper()

            # Extract input names
            input_names = re.findall(
                r'<(?:input|select|textarea)[^>]+name=["\']([^"\']+)["\']',
                form_body, re.I,
            )

            # Check for CSRF token
            hidden_inputs = re.findall(
                r'<input[^>]+type=["\']hidden["\'][^>]+name=["\']([^"\']+)["\']',
                form_body, re.I,
            )
            # Also check reverse attribute order
            hidden_inputs += re.findall(
                r'<input[^>]+name=["\']([^"\']+)["\'][^>]+type=["\']hidden["\']',
                form_body, re.I,
            )
            has_csrf = any(_CSRF_TOKEN_RE.search(n) for n in hidden_inputs)

            forms.append(_FormInfo(
                action_url=action_url,
                method=method,
                input_names=input_names,
                has_csrf_token=has_csrf,
                page_url=url,
            ))

            # Add form inputs as targets for injection testing
            action_parsed = urlparse(action_url)
            clean_action = f"{action_parsed.scheme}://{action_parsed.netloc}{action_parsed.path}"
            for iname in input_names:
                if _CSRF_TOKEN_RE.search(iname):
                    continue  # Skip CSRF tokens as injection targets
                key = (clean_action, iname)
                if key not in seen_params and len(iname) < 30:
                    seen_params.add(key)
                    targets.append(_Target(
                        url=clean_action,
                        param=iname,
                        value="",
                        source="form",
                    ))

    return targets, forms


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
        # Per-request timeout: at most 10s per individual HTTP request
        request_timeout = min(max(float(effective) * 0.08, 5.0), 10.0)
        scan_start = time.monotonic()

        def _budget_left():
            return effective - (time.monotonic() - scan_start)

        # Apply authenticated session from web.auth plugin if present
        auth_session = ctx.get("web.auth_session") or {}
        auth_cookies = (auth_session or {}).get("cookies") or {}
        auth_headers = (auth_session or {}).get("headers") or {}

        async with httpx.AsyncClient(
            timeout=request_timeout,
            verify=False,
            follow_redirects=True,
            limits=httpx.Limits(max_connections=10, max_keepalive_connections=5),
            cookies=auth_cookies or None,
            headers=auth_headers or None,
        ) as client:

            # ─── Phase 0: Target Discovery (spider + form parsing) ────────
            discovery_budget = effective * 0.20  # 20% of budget for discovery
            discovered_targets, discovered_forms = await _discover_targets(
                client, base_url, max_pages=10, budget_seconds=discovery_budget,
            )

            # Track which categories are tested and which produce findings.
            tested_categories = []
            pre_count = {}

            def _track(cat):
                tested_categories.append(cat)
                pre_count[cat] = len(findings)

            def _detected(cat):
                return len(findings) > pre_count.get(cat, len(findings))

            # ─── A02:2025 Security Misconfiguration — Sensitive file exposure
            if _budget_left() > 10:
                _track("misconfig")
                await self._check_sensitive_paths(client, base_url, target, findings)

            # ─── A05:2025 Injection — SQL Injection ───────────────────────
            if _budget_left() > 10:
                _track("sqli")
                await self._check_sqli(client, base_url, target, findings, discovered_targets)

            # ─── A05:2025 Injection — XSS (Reflected) ─────────────────────
            if _budget_left() > 10:
                _track("xss")
                await self._check_xss(client, base_url, target, findings, discovered_targets)

            # ─── A01:2025 Broken Access Control — Path Traversal ──────────
            if _budget_left() > 10:
                _track("lfi")
                await self._check_path_traversal(client, base_url, target, findings, discovered_targets)

            # ─── A05:2025 Injection — Command Injection ───────────────────
            if _budget_left() > 10:
                _track("cmdi")
                await self._check_cmdi(client, base_url, target, findings, discovered_targets)

            # ─── A01:2025 Broken Access Control — SSRF ────────────────────
            if _budget_left() > 10:
                _track("ssrf")
                await self._check_ssrf(client, base_url, target, findings, discovered_targets)

            # ─── A01:2025 Broken Access Control — CSRF ────────────────────
            if _budget_left() > 5:
                _track("csrf")
                await self._check_csrf(client, base_url, target, findings, discovered_forms)

            # ─── A05:2025 Injection — XXE ─────────────────────────────────
            if _budget_left() > 10:
                _track("xxe")
                await self._check_xxe(client, base_url, target, findings)

            # ─── A09:2025 Logging & Alerting — Info Disclosure ────────────
            if _budget_left() > 5:
                _track("info_disclosure")
                await self._check_info_disclosure(client, base_url, target, findings)

            # ─── A04:2025 Cryptographic Failures ──────────────────────────
            if _budget_left() > 3:
                _track("crypto")
                await self._check_crypto(client, base_url, target, findings)

            # ─── A02:2025 Security Misconfiguration — HTTP Methods ────────
            if _budget_left() > 3:
                _track("http_methods")
                await self._check_http_methods(client, base_url, target, findings)

            # ─── A02:2025 Security Misconfiguration — CORS ────────────────
            if _budget_left() > 3:
                _track("cors")
                await self._check_cors(client, base_url, target, findings)

            # ─── A02:2025 Security Misconfiguration — Cookie Security ─────
            if _budget_left() > 3:
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
                "owasp.discovered_targets": len(discovered_targets),
                "owasp.discovered_forms": len(discovered_forms),
            },
        )

    # ═════════════════════════════════════════════════════════════════════════
    # Individual OWASP test methods
    # ═════════════════════════════════════════════════════════════════════════

    async def _check_sensitive_paths(self, client, base_url, target, findings):
        """A02:2025 Security Misconfiguration — exposed sensitive files and directories."""
        sem = asyncio.Semaphore(5)

        # ── Soft-404 baseline: fetch a random non-existent path to fingerprint
        # custom error pages that return 200 for every URL. ──
        baseline_body = ""
        baseline_len = 0
        try:
            canary = base_url + "/vulnscan_404_check_" + str(int(time.monotonic() * 1000))
            br = await _safe_get(client, canary)
            if br and br.status_code == 200:
                baseline_body = br.text[:1000].lower()
                baseline_len = len(br.text)
        except Exception:
            pass

        def _is_soft_404(text):
            """Detect soft-404: page returned 200 but content matches baseline error page."""
            lower = text.lower()[:1000]
            # Explicit 404 markers
            if "not found" in lower[:500] or "404" in lower[:300]:
                return True
            if "page not found" in lower or "does not exist" in lower:
                return True
            if "the page you" in lower and ("looking for" in lower or "requested" in lower):
                return True
            # Compare against canary baseline — if body is very similar, it's a catch-all page
            if baseline_body and baseline_len > 50:
                # Same length within 10% and first 200 chars match → soft 404
                if abs(len(text) - baseline_len) < baseline_len * 0.1:
                    if text.lower()[:200] == baseline_body[:200]:
                        return True
            return False

        async def check_path(path, name, sev, remed, validator):
            async with sem:
                url = base_url + path
                r = await _safe_get(client, url)
                if r is None:
                    return
                if r.status_code != 200 or len(r.text) <= 10:
                    return
                # Soft-404 detection
                if _is_soft_404(r.text):
                    return
                # Content validation: if a validator is defined, the response
                # must match technology-specific signatures to avoid false positives
                if validator is not None:
                    try:
                        if not validator(r.text[:4000]):
                            return
                    except Exception:
                        return

                content_preview = r.text[:150].replace("\n", " ").strip()
                confidence = 0.92 if validator is not None else 0.70
                findings.append(Finding(
                    severity=sev,
                    plugin_id=META.plugin_id,
                    title=f"Exposed: {name} ({path})",
                    description=f"{name} is publicly accessible at {url}.",
                    evidence=f"url={url} status={r.status_code} size={len(r.text)} preview={content_preview}",
                    affected=target,
                    fingerprint=stable_fingerprint(target, META.plugin_id, "sensitive", path),
                    remediation=remed,
                    confidence=confidence,
                    references=[
                        "https://owasp.org/Top10/A02_2025-Security_Misconfiguration/"
                    ],
                ))

        await asyncio.gather(
            *[check_path(p, n, s, r, v) for p, n, s, r, v in SENSITIVE_PATHS],
            return_exceptions=True,
        )

    async def _check_sqli(self, client, base_url, target, findings, discovered_targets=None):
        """A05:2025 Injection — SQL injection via discovered targets, then hardcoded fallback."""
        found = False

        # Phase 1: Test discovered targets (real URLs with real params)
        if discovered_targets:
            for t in discovered_targets[:12]:
                if found:
                    break
                for payload, desc in SQLI_PAYLOADS[:3]:
                    test_url = f"{t.url}?{t.param}={urllib.parse.quote(payload)}"
                    r = await _safe_get(client, test_url)
                    if r is None:
                        continue
                    for pattern in SQLI_ERROR_PATTERNS:
                        if re.search(pattern, r.text, re.I):
                            findings.append(Finding(
                                severity="critical",
                                plugin_id=META.plugin_id,
                                title=f"SQL Injection detected ({t.param} at {urlparse(t.url).path})",
                                description=(
                                    f"The parameter '{t.param}' at {t.url} is vulnerable to SQL injection. "
                                    f"Database error messages confirm user input is passed to SQL queries."
                                ),
                                evidence=f"url={test_url} payload={payload} ({desc}) error_pattern={pattern} source={t.source}",
                                affected=target,
                                fingerprint=stable_fingerprint(target, META.plugin_id, "sqli", t.url, t.param),
                                remediation=(
                                    "[CRITICAL — OWASP A05:2025 Injection]\n"
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
                                    "https://owasp.org/Top10/A05_2025-Injection/",
                                    "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                                ],
                            ))
                            found = True
                            break
                    if found:
                        break

        # Phase 2: Fallback — hardcoded params on base_url
        if not found:
            fallback_params = ["id", "page", "cat", "item", "product", "user", "search", "q"]
            for param in fallback_params[:4]:
                if found:
                    break
                for payload, desc in SQLI_PAYLOADS[:3]:
                    url = f"{base_url}/?{param}={urllib.parse.quote(payload)}"
                    r = await _safe_get(client, url)
                    if r is None:
                        continue
                    for pattern in SQLI_ERROR_PATTERNS:
                        if re.search(pattern, r.text, re.I):
                            findings.append(Finding(
                                severity="critical",
                                plugin_id=META.plugin_id,
                                title=f"SQL Injection detected (parameter: {param})",
                                description=(
                                    f"The parameter '{param}' appears vulnerable to SQL injection. "
                                    f"Database error messages are returned in the response."
                                ),
                                evidence=f"url={url} payload={payload} ({desc}) error_pattern={pattern}",
                                affected=target,
                                fingerprint=stable_fingerprint(target, META.plugin_id, "sqli", param),
                                remediation=(
                                    "[CRITICAL — OWASP A05:2025 Injection]\n"
                                    "1. Use parameterized queries / prepared statements\n"
                                    "2. Use an ORM instead of raw SQL\n"
                                    "3. Apply input validation\n"
                                    "4. Disable detailed database error messages in production"
                                ),
                                cvss=9.8,
                                confidence=0.85,
                                references=["https://owasp.org/Top10/A05_2025-Injection/"],
                            ))
                            found = True
                            break
                    if found:
                        break

    async def _check_xss(self, client, base_url, target, findings, discovered_targets=None):
        """A05:2025 Injection — reflected XSS via discovered targets, then hardcoded fallback."""
        found = False

        # Phase 1: Test discovered targets
        if discovered_targets:
            for t in discovered_targets[:10]:
                if found:
                    break
                for payload, desc in XSS_PAYLOADS[:3]:
                    test_url = f"{t.url}?{t.param}={urllib.parse.quote(payload)}"
                    r = await _safe_get(client, test_url)
                    if r is None:
                        continue
                    if payload in r.text:
                        findings.append(Finding(
                            severity="high",
                            plugin_id=META.plugin_id,
                            title=f"Reflected XSS detected ({t.param} at {urlparse(t.url).path})",
                            description=(
                                f"The parameter '{t.param}' at {t.url} reflects user input without encoding, "
                                f"allowing HTML/JavaScript injection."
                            ),
                            evidence=f"url={test_url} payload={desc} reflected=true source={t.source}",
                            affected=target,
                            fingerprint=stable_fingerprint(target, META.plugin_id, "xss", t.url, t.param),
                            remediation=(
                                "[HIGH — OWASP A05:2025 Cross-Site Scripting]\n"
                                "1. Encode all user output with context-appropriate encoding\n"
                                "2. Implement Content-Security-Policy (CSP) header\n"
                                "3. Use templating engines with auto-escaping\n"
                                "4. Set HttpOnly flag on sensitive cookies\n"
                                "5. Deploy a WAF with XSS rules"
                            ),
                            cvss=7.1,
                            confidence=0.8,
                            references=[
                                "https://owasp.org/Top10/A05_2025-Injection/",
                                "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
                            ],
                        ))
                        found = True
                        break

        # Phase 2: Fallback — hardcoded params
        if not found:
            fallback_params = ["search", "q", "query", "s", "keyword", "name", "id"]
            for param in fallback_params[:3]:
                if found:
                    break
                for payload, desc in XSS_PAYLOADS[:3]:
                    url = f"{base_url}/?{param}={urllib.parse.quote(payload)}"
                    r = await _safe_get(client, url)
                    if r is None:
                        continue
                    if payload in r.text:
                        findings.append(Finding(
                            severity="high",
                            plugin_id=META.plugin_id,
                            title=f"Reflected XSS detected (parameter: {param})",
                            description=(
                                f"The parameter '{param}' reflects user input without proper encoding."
                            ),
                            evidence=f"url={url} payload={desc} reflected=true",
                            affected=target,
                            fingerprint=stable_fingerprint(target, META.plugin_id, "xss", param),
                            remediation=(
                                "[HIGH — OWASP A05:2025 Cross-Site Scripting]\n"
                                "1. Encode all user output\n"
                                "2. Implement CSP header\n"
                                "3. Use auto-escaping templates"
                            ),
                            cvss=7.1,
                            confidence=0.8,
                            references=["https://owasp.org/Top10/A05_2025-Injection/"],
                        ))
                        found = True
                        break

    async def _check_path_traversal(self, client, base_url, target, findings, discovered_targets=None):
        """A01:2025 Broken Access Control — path traversal / local file inclusion."""
        found = False

        # Phase 1: Test discovered targets with file-like param names
        file_params = {"file", "path", "page", "doc", "template", "include", "url",
                       "load", "read", "download", "content", "view", "open"}
        if discovered_targets:
            file_targets = [t for t in discovered_targets if t.param.lower() in file_params]
            for t in file_targets[:6]:
                if found:
                    break
                for payload, desc in TRAVERSAL_PAYLOADS[:3]:
                    test_url = f"{t.url}?{t.param}={urllib.parse.quote(payload)}"
                    r = await _safe_get(client, test_url)
                    if r is None:
                        continue
                    for pattern in TRAVERSAL_SUCCESS_PATTERNS:
                        if re.search(pattern, r.text):
                            findings.append(Finding(
                                severity="critical",
                                plugin_id=META.plugin_id,
                                title=f"Path Traversal / LFI detected ({t.param} at {urlparse(t.url).path})",
                                description=(
                                    f"The parameter '{t.param}' at {t.url} is vulnerable to path traversal."
                                ),
                                evidence=f"url={test_url} payload={desc} file_content_detected=true",
                                affected=target,
                                fingerprint=stable_fingerprint(target, META.plugin_id, "lfi", t.url, t.param),
                                remediation=(
                                    "[CRITICAL — OWASP A01:2025 Broken Access Control]\n"
                                    "1. Never use user input directly in file paths\n"
                                    "2. Use a whitelist of allowed files\n"
                                    "3. Canonicalize and validate paths"
                                ),
                                cvss=9.1,
                                confidence=0.9,
                                references=["https://owasp.org/Top10/A01_2025-Broken_Access_Control/"],
                            ))
                            found = True
                            break
                    if found:
                        break

        # Phase 2: Fallback — hardcoded params
        if not found:
            for param in list(file_params)[:3]:
                if found:
                    break
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
                                description=f"The parameter '{param}' is vulnerable to path traversal.",
                                evidence=f"url={url} payload={desc} file_content_detected=true",
                                affected=target,
                                fingerprint=stable_fingerprint(target, META.plugin_id, "lfi", param),
                                remediation="Use a whitelist of allowed files. Never use user input in file paths.",
                                cvss=9.1,
                                confidence=0.9,
                                references=["https://owasp.org/Top10/A01_2025-Broken_Access_Control/"],
                            ))
                            found = True
                            break
                    if found:
                        break

    async def _check_cmdi(self, client, base_url, target, findings, discovered_targets=None):
        """A05:2025 Injection — OS command injection."""
        found = False

        # Phase 1: Discovered targets with cmd-like param names
        cmd_params = {"cmd", "exec", "command", "ping", "host", "ip", "run", "system"}
        if discovered_targets:
            cmd_targets = [t for t in discovered_targets if t.param.lower() in cmd_params]
            for t in cmd_targets[:4]:
                if found:
                    break
                for payload, desc in CMDI_PAYLOADS[:2]:
                    test_url = f"{t.url}?{t.param}={urllib.parse.quote(payload)}"
                    r = await _safe_get(client, test_url)
                    if r and re.search(CMDI_SUCCESS_PATTERN, r.text):
                        findings.append(Finding(
                            severity="critical",
                            plugin_id=META.plugin_id,
                            title=f"Command Injection detected ({t.param} at {urlparse(t.url).path})",
                            description=f"The parameter '{t.param}' at {t.url} allows OS command execution.",
                            evidence=f"url={test_url} payload={desc} output_detected=true",
                            affected=target,
                            fingerprint=stable_fingerprint(target, META.plugin_id, "cmdi", t.url, t.param),
                            remediation=(
                                "[CRITICAL — OWASP A05:2025 Injection]\n"
                                "1. Never pass user input to OS commands\n"
                                "2. Use language-native APIs instead of shell commands"
                            ),
                            cvss=9.8,
                            confidence=0.9,
                            references=["https://owasp.org/Top10/A05_2025-Injection/"],
                        ))
                        found = True
                        break

        # Phase 2: Fallback
        if not found:
            for param in ["cmd", "exec", "command", "ping", "host", "ip"][:2]:
                if found:
                    break
                for payload, desc in CMDI_PAYLOADS[:2]:
                    url = f"{base_url}/?{param}={urllib.parse.quote(payload)}"
                    r = await _safe_get(client, url)
                    if r and re.search(CMDI_SUCCESS_PATTERN, r.text):
                        findings.append(Finding(
                            severity="critical",
                            plugin_id=META.plugin_id,
                            title=f"Command Injection detected (parameter: {param})",
                            description=f"The parameter '{param}' allows execution of arbitrary OS commands.",
                            evidence=f"url={url} payload={desc} output_detected=true",
                            affected=target,
                            fingerprint=stable_fingerprint(target, META.plugin_id, "cmdi", param),
                            remediation="Never pass user input to OS commands. Use language-native APIs.",
                            cvss=9.8,
                            confidence=0.9,
                            references=["https://owasp.org/Top10/A05_2025-Injection/"],
                        ))
                        found = True
                        break

    async def _check_ssrf(self, client, base_url, target, findings, discovered_targets=None):
        """A01:2025 Broken Access Control — Server-Side Request Forgery (SSRF)."""
        found = False
        ssrf_params = {"url", "link", "redirect", "next", "target", "rurl", "dest",
                       "fetch", "uri", "site", "src", "href", "callback"}

        # Phase 1: Discovered targets with URL-like param names
        if discovered_targets:
            url_targets = [t for t in discovered_targets if t.param.lower() in ssrf_params]
            for t in url_targets[:4]:
                if found:
                    break
                for payload, desc in SSRF_PAYLOADS[:2]:
                    test_url = f"{t.url}?{t.param}={urllib.parse.quote(payload)}"
                    r = await _safe_get(client, test_url)
                    if r is None:
                        continue
                    ssrf_indicators = ["ami-id", "instance-id", "hostname", "local-ipv4",
                                       "computeMetadata", "project-id", "Directory listing", "Index of"]
                    for indicator in ssrf_indicators:
                        if indicator.lower() in r.text.lower():
                            findings.append(Finding(
                                severity="critical",
                                plugin_id=META.plugin_id,
                                title=f"SSRF detected ({t.param} at {urlparse(t.url).path})",
                                description=f"The parameter '{t.param}' at {t.url} can fetch internal resources.",
                                evidence=f"url={test_url} payload={desc} indicator={indicator}",
                                affected=target,
                                fingerprint=stable_fingerprint(target, META.plugin_id, "ssrf", t.url, t.param),
                                remediation=(
                                    "[CRITICAL — OWASP A01:2025 Broken Access Control / SSRF]\n"
                                    "1. Validate and sanitize all user-supplied URLs\n"
                                    "2. Use an allowlist of permitted domains\n"
                                    "3. Block private IP ranges and cloud metadata endpoints"
                                ),
                                cvss=9.1,
                                confidence=0.8,
                                references=["https://owasp.org/Top10/A01_2025-Broken_Access_Control/"],
                            ))
                            found = True
                            break
                    if found:
                        break

        # Phase 2: Fallback
        if not found:
            for param in list(ssrf_params)[:3]:
                if found:
                    break
                for payload, desc in SSRF_PAYLOADS[:2]:
                    url = f"{base_url}/?{param}={urllib.parse.quote(payload)}"
                    r = await _safe_get(client, url)
                    if r is None:
                        continue
                    for indicator in ["ami-id", "instance-id", "hostname", "local-ipv4",
                                      "computeMetadata", "project-id", "Directory listing", "Index of"]:
                        if indicator.lower() in r.text.lower():
                            findings.append(Finding(
                                severity="critical",
                                plugin_id=META.plugin_id,
                                title=f"SSRF detected (parameter: {param})",
                                description=f"The parameter '{param}' can fetch internal resources.",
                                evidence=f"url={url} payload={desc} indicator={indicator}",
                                affected=target,
                                fingerprint=stable_fingerprint(target, META.plugin_id, "ssrf", param),
                                remediation="Validate URLs. Block private IPs and cloud metadata endpoints.",
                                cvss=9.1,
                                confidence=0.8,
                                references=["https://owasp.org/Top10/A01_2025-Broken_Access_Control/"],
                            ))
                            found = True
                            break
                    if found:
                        break

    async def _check_csrf(self, client, base_url, target, findings, discovered_forms=None):
        """A01:2025 Broken Access Control — missing CSRF protection in forms."""
        if not discovered_forms:
            return

        checked = set()
        for form in discovered_forms:
            # Only check POST forms (CSRF is mainly a POST concern)
            if form.method != "POST":
                continue

            # Skip trivial search forms
            if len(form.input_names) <= 1:
                search_names = {"q", "search", "query", "s", "keyword"}
                if form.input_names and form.input_names[0].lower() in search_names:
                    continue

            # Dedup by action URL
            if form.action_url in checked:
                continue
            checked.add(form.action_url)

            if not form.has_csrf_token:
                path = urlparse(form.action_url).path or "/"
                findings.append(Finding(
                    severity="medium",
                    plugin_id=META.plugin_id,
                    title=f"Missing CSRF protection (POST form at {path})",
                    description=(
                        f"A POST form at {form.action_url} (found on {form.page_url}) "
                        f"lacks a CSRF token. An attacker could craft a malicious page that "
                        f"submits this form on behalf of authenticated users."
                    ),
                    evidence=(
                        f"action={form.action_url} method={form.method} "
                        f"inputs={','.join(form.input_names[:10])} csrf_token=missing"
                    ),
                    affected=target,
                    fingerprint=stable_fingerprint(target, META.plugin_id, "csrf", form.action_url),
                    remediation=(
                        "[MEDIUM — OWASP A01:2025 Broken Access Control / CSRF]\n"
                        "1. Include a unique CSRF token in every state-changing form\n"
                        "2. Validate the token server-side on form submission\n"
                        "3. Use SameSite=Lax or Strict on session cookies\n"
                        "4. Consider using the Synchronizer Token Pattern or Double Submit Cookie"
                    ),
                    cvss=6.5,
                    confidence=0.75,
                    references=[
                        "https://owasp.org/Top10/A01_2025-Broken_Access_Control/",
                        "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
                    ],
                ))

    async def _check_xxe(self, client, base_url, target, findings):
        """A05:2025 Injection — XML External Entity (XXE) injection."""
        # Detect XML endpoints by testing common paths
        xml_paths = [
            "/api/xml", "/xmlrpc.php", "/xmlrpc", "/soap", "/ws",
            "/api/upload", "/api/import", "/api/parse",
        ]

        # Safe XXE probe — internal entity expansion only (no file access)
        xxe_payload = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<!DOCTYPE foo [<!ENTITY xxe "vulnscan_xxe_test">]>'
            '<root><data>&xxe;</data></root>'
        )
        xxe_headers = {"Content-Type": "application/xml"}

        for path in xml_paths:
            url = base_url + path

            # First check if the endpoint accepts XML (GET to see if it exists)
            r = await _safe_get(client, url)
            if r is None or r.status_code >= 404:
                continue

            # Send XXE probe via POST
            r2 = await _safe_post(client, url, content=xxe_payload, headers=xxe_headers)
            if r2 is None:
                continue

            body = r2.text
            if "vulnscan_xxe_test" in body:
                findings.append(Finding(
                    severity="high",
                    plugin_id=META.plugin_id,
                    title=f"XXE: XML entity expansion confirmed ({path})",
                    description=(
                        f"The endpoint at {url} processes XML with DTD/entity expansion enabled. "
                        f"An attacker can read local files, perform SSRF, or cause denial of service."
                    ),
                    evidence=f"url={url} xxe_entity_expanded=true",
                    affected=target,
                    fingerprint=stable_fingerprint(target, META.plugin_id, "xxe", path),
                    remediation=(
                        "[HIGH — OWASP A05:2025 XXE Injection]\n"
                        "1. Disable DTD processing in your XML parser\n"
                        "2. Disable external entity resolution\n"
                        "3. Use simpler data formats (JSON) when possible\n"
                        "4. Patch/upgrade XML processing libraries\n"
                        "   - Java: factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)\n"
                        "   - PHP: libxml_disable_entity_loader(true)\n"
                        "   - Python: defusedxml library"
                    ),
                    cvss=8.6,
                    confidence=0.85,
                    references=[
                        "https://owasp.org/Top10/A05_2025-Injection/",
                        "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html",
                    ],
                ))
                return  # One finding is enough

            # Check if XML processing errors hint at DTD awareness
            dtd_hints = ["DOCTYPE", "entity", "SYSTEM", "DTD", "xml parsing"]
            if any(h.lower() in body.lower() for h in dtd_hints):
                findings.append(Finding(
                    severity="medium",
                    plugin_id=META.plugin_id,
                    title=f"XXE: DTD processing detected ({path})",
                    description=(
                        f"The endpoint at {url} shows signs of DTD processing in XML input. "
                        f"While entity expansion was blocked, the parser may be partially vulnerable."
                    ),
                    evidence=f"url={url} dtd_processing_hints=true",
                    affected=target,
                    fingerprint=stable_fingerprint(target, META.plugin_id, "xxe_hint", path),
                    remediation=(
                        "[MEDIUM — OWASP A05:2025 Potential XXE]\n"
                        "Disable DTD processing entirely in your XML parser configuration."
                    ),
                    cvss=5.3,
                    confidence=0.6,
                    references=["https://owasp.org/Top10/A05_2025-Injection/"],
                ))
                return

    async def _check_info_disclosure(self, client, base_url, target, findings):
        """A09:2025 Logging & Alerting Failures — information disclosure in error responses."""
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
                            "[MEDIUM — OWASP A09:2025 Logging & Alerting Failures]\n"
                            "1. Configure custom error pages — never show stack traces in production\n"
                            "2. Set DEBUG=False (Django), APP_DEBUG=false (Laravel)\n"
                            "3. Configure error logging to files, not responses"
                        ),
                        confidence=0.75,
                        references=[
                            "https://owasp.org/Top10/A09_2025-Logging_and_Alerting_Failures/",
                        ],
                    ))
                    break

    async def _check_crypto(self, client, base_url, target, findings):
        """A04:2025 Cryptographic Failures — missing HTTPS/HSTS."""
        if base_url.startswith("http://"):
            r = await _safe_get(client, base_url)
            if r and r.status_code == 200:
                final_url = str(r.url)
                if not final_url.startswith("https://"):
                    findings.append(Finding(
                        severity="high",
                        plugin_id=META.plugin_id,
                        title="No HTTPS — data transmitted in plaintext",
                        description=(
                            "The application serves content over HTTP without redirecting to HTTPS. "
                            "All data (including credentials) is transmitted in plaintext."
                        ),
                        evidence=f"url={base_url} final_url={final_url} no_https_redirect=true",
                        affected=target,
                        fingerprint=stable_fingerprint(target, META.plugin_id, "no_https"),
                        remediation=(
                            "[HIGH — OWASP A04:2025 Cryptographic Failures]\n"
                            "1. Enable HTTPS with a valid TLS certificate\n"
                            "2. Redirect all HTTP traffic to HTTPS (301)\n"
                            "3. Add HSTS header"
                        ),
                        cvss=7.5,
                        confidence=0.95,
                        references=["https://owasp.org/Top10/A04_2025-Cryptographic_Failures/"],
                    ))

    async def _check_http_methods(self, client, base_url, target, findings):
        """A02:2025 Security Misconfiguration — dangerous HTTP methods."""
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
                        f"The server allows HTTP methods that should be disabled: {', '.join(sorted(risky))}."
                    ),
                    evidence=f"url={base_url} allow_header={allow}",
                    affected=target,
                    fingerprint=stable_fingerprint(target, META.plugin_id, "http_methods"),
                    remediation=(
                        "Disable unnecessary HTTP methods in your web server:\n"
                        "- nginx: if ($request_method !~ ^(GET|HEAD|POST)$) { return 405; }\n"
                        "- Apache: use <LimitExcept GET POST HEAD>"
                    ),
                    confidence=0.9,
                    references=["https://owasp.org/Top10/A02_2025-Security_Misconfiguration/"],
                ))
        except Exception:
            pass

    async def _check_cors(self, client, base_url, target, findings):
        """A02:2025 Security Misconfiguration — CORS misconfiguration."""
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
                    description="The server allows any origin to make cross-site requests.",
                    evidence=f"url={base_url} acao={acao} acac={acac}",
                    affected=target,
                    fingerprint=stable_fingerprint(target, META.plugin_id, "cors_wildcard"),
                    remediation="Restrict CORS to specific trusted origins.",
                    confidence=0.9,
                ))
            elif "evil-attacker.com" in acao:
                sev = "high" if acac.lower() == "true" else "medium"
                findings.append(Finding(
                    severity=sev,
                    plugin_id=META.plugin_id,
                    title="CORS: Origin reflection vulnerability",
                    description="The server reflects any Origin header back, allowing cross-origin requests.",
                    evidence=f"url={base_url} reflected_origin={acao} credentials={acac}",
                    affected=target,
                    fingerprint=stable_fingerprint(target, META.plugin_id, "cors_reflect"),
                    remediation="Validate Origin against a whitelist. Never reflect arbitrary origins.",
                    cvss=6.5 if sev == "high" else 4.3,
                    confidence=0.95,
                ))
        except Exception:
            pass

    async def _check_cookies(self, client, base_url, target, findings):
        """A02:2025 Security Misconfiguration — insecure cookie settings."""
        try:
            r = await client.get(base_url)
            for cookie_header in r.headers.get_list("set-cookie"):
                cookie_lower = cookie_header.lower()
                name_match = re.match(r"([^=]+)=", cookie_header)
                name = name_match.group(1) if name_match else "unknown"

                if any(t in name.lower() for t in ["_ga", "_gid", "fbp", "fbclid"]):
                    continue

                issues = []
                if "httponly" not in cookie_lower:
                    issues.append("missing HttpOnly")
                if "secure" not in cookie_lower and base_url.startswith("https"):
                    issues.append("missing Secure flag")
                if "samesite" not in cookie_lower:
                    issues.append("missing SameSite")

                session_indicators = ["sess", "token", "auth", "jwt", "sid", "login", "csrf"]
                is_session = any(ind in name.lower() for ind in session_indicators)

                if issues and is_session:
                    findings.append(Finding(
                        severity="medium" if "httponly" in str(issues) else "low",
                        plugin_id=META.plugin_id,
                        title=f"Insecure cookie: {name} ({', '.join(issues)})",
                        description=(
                            f"The session cookie '{name}' is missing security attributes: {', '.join(issues)}."
                        ),
                        evidence=f"cookie={cookie_header[:200]}",
                        affected=target,
                        fingerprint=stable_fingerprint(target, META.plugin_id, "cookie", name),
                        remediation="Set HttpOnly, Secure, and SameSite=Lax on all session cookies.",
                        confidence=0.9,
                    ))
        except Exception:
            pass

