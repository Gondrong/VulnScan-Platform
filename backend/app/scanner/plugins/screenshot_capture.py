"""
Web Service Metadata Capture Plugin
Captures key metadata from discovered HTTP services: final URL after
redirects, page title, response size, status code, detected technologies,
interesting headers, and visible text content.

This is a lightweight alternative to browser-based screenshots, providing
structured web service inventory data for reports and the frontend.

Safety: All probes are GET-only and read-only. No modifications are made
to the target system.
"""
import re

import httpx

from app.scanner.plugins.base import Plugin, PluginMeta, PluginResult, Finding
from app.scanner.context import stable_fingerprint

META = PluginMeta(
    plugin_id="recon.screenshot",
    name="Web Service Metadata Capture",
    category="recon",
    depends_on=["fingerprint.http"],
    consumes=["fingerprint.http", "net.open_ports"],
    provides=["recon.web_metadata"],
    enabled_by_default=True,
    timeout_seconds=20.0,
)

# ── Admin panel keywords ──────────────────────────────────────────────
_ADMIN_KEYWORDS = [
    "admin panel", "admin dashboard", "administration",
    "admin console", "control panel", "cpanel", "webmin",
    "phpmyadmin", "adminer", "wp-admin", "administrator",
    "management console", "server status", "dashboard",
    "admin login", "back office", "backoffice",
]

# ── Stack trace / error keywords ──────────────────────────────────────
_ERROR_KEYWORDS = [
    "Traceback (most recent call last)",
    "Exception in thread",
    "at java.", "at org.", "at com.",
    "Fatal error:", "Parse error:", "Warning:",
    "stack trace", "Stack Trace",
    "SQLSTATE[", "mysql_", "pg_query",
    "System.NullReferenceException",
    "System.Exception",
    "Unhandled Exception",
    "Application Error",
    "Server Error in",
    "RuntimeError",
    "SyntaxError",
    "TypeError:",
    "node_modules/",
    "vendor/",
    "Debug mode is on",
    "DJANGO_SETTINGS_MODULE",
    "APP_DEBUG",
]

# ── Technology indicators in headers ──────────────────────────────────
_HEADER_TECH_MAP = {
    "x-powered-by": "Powered By",
    "x-aspnet-version": "ASP.NET",
    "x-drupal-cache": "Drupal",
    "x-generator": "Generator",
    "x-varnish": "Varnish Cache",
    "x-cache": "CDN/Cache",
    "cf-ray": "Cloudflare",
    "x-amz-cf-id": "AWS CloudFront",
    "x-vercel-id": "Vercel",
    "x-netlify-request-id": "Netlify",
    "server": "Server",
}

# ── Interesting headers to capture ────────────────────────────────────
_INTERESTING_HEADERS = [
    "server", "x-powered-by", "x-aspnet-version",
    "x-generator", "x-drupal-cache", "x-varnish",
    "x-cache", "cf-ray", "x-amz-cf-id", "x-vercel-id",
    "x-netlify-request-id", "x-frame-options",
    "content-security-policy", "strict-transport-security",
    "x-content-type-options", "access-control-allow-origin",
    "set-cookie", "www-authenticate",
]


def _strip_html(html: str) -> str:
    """Strip HTML tags and return visible text content."""
    # Remove script and style blocks entirely
    text = re.sub(r"<script[^>]*>.*?</script>", " ", html, flags=re.DOTALL | re.I)
    text = re.sub(r"<style[^>]*>.*?</style>", " ", text, flags=re.DOTALL | re.I)
    # Remove HTML comments
    text = re.sub(r"<!--.*?-->", " ", text, flags=re.DOTALL)
    # Remove HTML tags
    text = re.sub(r"<[^>]+>", " ", text)
    # Decode common HTML entities
    text = text.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">")
    text = text.replace("&quot;", '"').replace("&#39;", "'").replace("&nbsp;", " ")
    # Collapse whitespace
    text = re.sub(r"\s+", " ", text).strip()
    return text


def _extract_title(html: str) -> str:
    """Extract the page title from HTML."""
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.DOTALL)
    if m:
        title = m.group(1).strip()
        # Clean up whitespace
        title = re.sub(r"\s+", " ", title)
        return title[:200]
    return ""


def _has_login_form(html: str) -> bool:
    """Detect if the page contains a login form."""
    html_lower = html.lower()
    # Check for password input field
    has_password = bool(re.search(
        r'<input[^>]*type\s*=\s*["\']password["\']', html_lower
    ))
    # Check for form element
    has_form = "<form" in html_lower
    return has_password and has_form


def _detect_admin_panel(html: str, title: str) -> bool:
    """Detect if the page is an admin panel."""
    text_lower = (html[:5000] + " " + title).lower()
    return any(kw in text_lower for kw in _ADMIN_KEYWORDS)


def _detect_stack_trace(text: str) -> list[str]:
    """Detect stack traces or error messages in page text."""
    found = []
    for kw in _ERROR_KEYWORDS:
        if kw.lower() in text.lower():
            found.append(kw)
    return found


class Check(Plugin):
    async def run(self, target: str, ctx) -> PluginResult:
        http_data = (ctx.get("fingerprint.http", {}) or {}).get("http", [])
        ports = ctx.get("net.open_ports", []) or []
        target_raw = ctx.get("target_raw", target)
        findings: list[Finding] = []
        web_metadata: list[dict] = []

        # Determine URLs to capture
        urls_to_check = []
        if re.match(r"^https?://", target_raw, re.I):
            urls_to_check.append(target_raw.rstrip("/") + "/")
        else:
            for item in http_data:
                url = item.get("url", "")
                if url:
                    urls_to_check.append(url.rstrip("/") + "/")
            if not urls_to_check:
                web_ports = [
                    p for p in ports
                    if p in (80, 443, 8080, 8443, 3000, 5000, 8000)
                ]
                for p in web_ports:
                    scheme = "https" if p in (443, 8443) else "http"
                    urls_to_check.append(f"{scheme}://{target}:{p}/")

        if not urls_to_check:
            return PluginResult(artifacts={"recon.web_metadata": []})

        try:
            async with httpx.AsyncClient(
                timeout=min(ctx.policy.timeout_seconds, 10),
                verify=False,
                follow_redirects=True,
                limits=httpx.Limits(max_connections=5),
            ) as client:
                for url in urls_to_check[:5]:
                    try:
                        metadata = await self._capture_metadata(
                            client, url, target
                        )
                        if metadata:
                            web_metadata.append(metadata)

                            # Generate info finding for the web service
                            self._add_service_finding(
                                findings, metadata, target
                            )

                            # Check for security concerns
                            self._check_security_concerns(
                                findings, metadata, target
                            )
                    except Exception:
                        continue

        except Exception:
            pass

        return PluginResult(
            findings=findings,
            artifacts={"recon.web_metadata": web_metadata},
        )

    async def _capture_metadata(
        self, client: httpx.AsyncClient, url: str, target: str
    ) -> dict | None:
        """Capture metadata from a single URL."""
        try:
            r = await client.get(url)
        except Exception:
            return None

        html = r.text or ""
        title = _extract_title(html)
        visible_text = _strip_html(html)[:2000]

        # Collect interesting headers
        interesting = {}
        detected_tech = []
        for hdr in _INTERESTING_HEADERS:
            val = r.headers.get(hdr)
            if val:
                interesting[hdr] = val[:200]
                # Map to technology
                tech_name = _HEADER_TECH_MAP.get(hdr)
                if tech_name:
                    detected_tech.append(f"{tech_name}: {val[:100]}")

        # Detect page type
        has_login = _has_login_form(html)
        is_admin = _detect_admin_panel(html, title)
        error_indicators = _detect_stack_trace(html + " " + visible_text)

        # Track redirect chain
        final_url = str(r.url)
        redirect_chain = []
        for resp in r.history:
            redirect_chain.append({
                "url": str(resp.url),
                "status": resp.status_code,
            })

        metadata = {
            "original_url": url,
            "final_url": final_url,
            "status_code": r.status_code,
            "title": title,
            "response_size": len(html),
            "visible_text_preview": visible_text[:500],
            "interesting_headers": interesting,
            "detected_technologies": detected_tech,
            "has_login_form": has_login,
            "is_admin_panel": is_admin,
            "has_error_traces": len(error_indicators) > 0,
            "error_indicators": error_indicators[:5],
            "redirect_chain": redirect_chain,
            "redirected": final_url != url,
            "content_type": r.headers.get("content-type", ""),
        }

        return metadata

    def _add_service_finding(
        self, findings: list[Finding], metadata: dict, target: str
    ) -> None:
        """Add an info finding summarizing a discovered web service."""
        url = metadata["final_url"]
        title = metadata["title"] or "(no title)"
        status = metadata["status_code"]
        size = metadata["response_size"]
        tech_str = ", ".join(metadata["detected_technologies"][:5]) or "none detected"

        page_type_parts = []
        if metadata["has_login_form"]:
            page_type_parts.append("login page")
        if metadata["is_admin_panel"]:
            page_type_parts.append("admin panel")
        if metadata["has_error_traces"]:
            page_type_parts.append("error page")
        page_type = ", ".join(page_type_parts) if page_type_parts else "standard"

        redirect_info = ""
        if metadata["redirected"]:
            redirect_info = f" (redirected from {metadata['original_url']})"

        fp = stable_fingerprint(target, META.plugin_id, "service", url)
        findings.append(Finding(
            severity="info",
            plugin_id=META.plugin_id,
            title=f"Web service: {title} [{status}]",
            description=(
                f"Discovered web service at {url}{redirect_info}. "
                f"Title: '{title}', Status: {status}, "
                f"Size: {size} bytes, Type: {page_type}, "
                f"Technologies: {tech_str}."
            ),
            evidence=(
                f"url={url} status={status} title={title} "
                f"size={size} type={page_type} tech={tech_str}"
            ),
            affected=target,
            fingerprint=fp,
            confidence=1.0,
            remediation=(
                f"[WEB SERVICE] {url}\n"
                f"[TITLE] {title}\n"
                f"[STATUS] {status}\n"
                f"[SIZE] {size} bytes\n"
                f"[TECHNOLOGIES] {tech_str}\n"
                f"[TYPE] {page_type}\n\n"
                "This is an informational finding documenting the web service inventory."
            ),
        ))

    def _check_security_concerns(
        self, findings: list[Finding], metadata: dict, target: str
    ) -> None:
        """Check for security concerns and generate medium findings."""
        url = metadata["final_url"]

        # 1. Exposed admin panel
        if metadata["is_admin_panel"]:
            fp = stable_fingerprint(
                target, META.plugin_id, "admin_panel", url
            )
            findings.append(Finding(
                severity="medium",
                plugin_id=META.plugin_id,
                title=f"Admin panel detected: {metadata['title'] or url}",
                description=(
                    f"An administration panel was detected at {url}. "
                    "Publicly accessible admin panels are a high-value target "
                    "for attackers attempting brute-force or credential stuffing."
                ),
                evidence=f"url={url} title={metadata['title']} admin=true",
                affected=target,
                fingerprint=fp,
                confidence=0.85,
                remediation=(
                    f"[AFFECTED] Admin panel at {url}\n\n"
                    "[RECOMMENDED ACTIONS]\n"
                    "1. Restrict admin access by IP address:\n"
                    "   Nginx: location /admin { allow 10.0.0.0/8; deny all; }\n"
                    "2. Enable multi-factor authentication (MFA)\n"
                    "3. Use a non-standard URL for the admin panel\n"
                    "4. Implement account lockout after failed attempts\n"
                    "5. Place admin behind a VPN or zero-trust network\n\n"
                    "[MONITORING] Enable logging for all admin access attempts"
                ),
                references=[
                    "https://owasp.org/www-project-web-security-testing-guide/"
                ],
            ))

        # 2. Login page without HTTPS
        if metadata["has_login_form"] and not url.startswith("https://"):
            fp = stable_fingerprint(
                target, META.plugin_id, "login_no_https", url
            )
            findings.append(Finding(
                severity="medium",
                plugin_id=META.plugin_id,
                title="Login page served over HTTP (no TLS)",
                description=(
                    f"A login page was detected at {url} served over plain HTTP. "
                    "Credentials submitted over HTTP are transmitted in cleartext "
                    "and can be intercepted by anyone on the network path."
                ),
                evidence=f"url={url} login=true https=false",
                affected=target,
                fingerprint=fp,
                confidence=0.95,
                remediation=(
                    f"[AFFECTED] Login page at {url} is not using HTTPS\n\n"
                    "[IMMEDIATE ACTION]\n"
                    "1. Enable HTTPS (TLS) on the web server\n"
                    "2. Obtain an SSL certificate (Let's Encrypt is free)\n"
                    "3. Redirect all HTTP traffic to HTTPS:\n"
                    "   Nginx: return 301 https://$server_name$request_uri;\n"
                    "4. Add HSTS header to prevent downgrade attacks\n\n"
                    "[WHY] Without TLS, usernames and passwords are sent in "
                    "cleartext and can be captured via network sniffing (Wireshark, "
                    "tcpdump) or MITM attacks."
                ),
                references=[
                    "https://owasp.org/www-project-web-security-testing-guide/"
                ],
            ))

        # 3. Error pages with stack traces
        if metadata["has_error_traces"] and metadata["error_indicators"]:
            indicators = metadata["error_indicators"]
            fp = stable_fingerprint(
                target, META.plugin_id, "stack_trace", url
            )
            findings.append(Finding(
                severity="medium",
                plugin_id=META.plugin_id,
                title="Error page exposes stack trace or debug info",
                description=(
                    f"The page at {url} contains error messages or stack traces "
                    f"that reveal internal application details. Indicators found: "
                    f"{', '.join(indicators[:3])}. This information helps attackers "
                    "understand the application's technology stack, file structure, "
                    "and potential vulnerability points."
                ),
                evidence=f"url={url} error_indicators={indicators[:5]}",
                affected=target,
                fingerprint=fp,
                confidence=0.80,
                remediation=(
                    f"[AFFECTED] Error/debug information exposed at {url}\n\n"
                    "[IMMEDIATE ACTION]\n"
                    "1. Disable debug mode in production:\n"
                    "   Django: DEBUG = False\n"
                    "   Laravel: APP_DEBUG=false\n"
                    "   Node.js: NODE_ENV=production\n"
                    "   Spring: logging.level.root=WARN\n\n"
                    "2. Configure custom error pages:\n"
                    "   - Return generic error messages to users\n"
                    "   - Log detailed errors server-side only\n\n"
                    "3. Review error handling middleware\n\n"
                    "[WHY] Stack traces reveal file paths, framework versions, "
                    "database types, and code structure — all valuable for attackers."
                ),
                references=[
                    "https://owasp.org/www-project-web-security-testing-guide/"
                ],
            ))
