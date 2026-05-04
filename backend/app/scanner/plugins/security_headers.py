"""
Security Headers Audit Plugin
Checks for missing or misconfigured HTTP security headers.
Zero false positive risk — headers either exist with correct values or they don't.
"""
import asyncio
import re
import ssl
import urllib.parse

from app.scanner.plugins.base import Plugin, PluginMeta, PluginResult, Finding
from app.scanner.context import stable_fingerprint

META = PluginMeta(
    plugin_id="web.security_headers",
    name="Security Headers Audit",
    category="web",
    depends_on=["fingerprint.http"],
    consumes=["fingerprint.http", "net.open_ports"],
    provides=["web.security_headers"],
    enabled_by_default=True,
    timeout_seconds=20.0,
)

# ── Security headers to check ──────────────────────────────────────────
# (header_name, severity_if_missing, description, remediation, reference)
_REQUIRED_HEADERS = [
    (
        "strict-transport-security",
        "high",
        "HTTP Strict Transport Security (HSTS) tells browsers to only connect via HTTPS. "
        "Without it, users are vulnerable to SSL stripping attacks (e.g., sslstrip, MITM on open WiFi).",
        "[FIX] Add HSTS header:\n"
        "  Nginx:   add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;\n"
        "  Apache:  Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\"\n"
        "  IIS:     Add via web.config customHeaders\n\n"
        "[NOTE] Start with a short max-age (3600) and increase after testing.\n"
        "Consider HSTS preload: https://hstspreload.org/",
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
    ),
    (
        "content-security-policy",
        "medium",
        "Content Security Policy (CSP) prevents XSS, clickjacking, and code injection by "
        "controlling which resources the browser is allowed to load.",
        "[FIX] Add a CSP header. Start with report-only mode:\n"
        "  Content-Security-Policy-Report-Only: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; report-uri /csp-report\n\n"
        "Then enforce after reviewing violations:\n"
        "  Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'\n\n"
        "[AVOID] unsafe-inline for scripts, unsafe-eval, wildcard (*) sources",
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
    ),
    (
        "x-content-type-options",
        "medium",
        "Without X-Content-Type-Options: nosniff, browsers may MIME-sniff responses and "
        "interpret uploaded files as executable scripts, enabling XSS attacks.",
        "[FIX] Add header:\n"
        "  X-Content-Type-Options: nosniff\n\n"
        "  Nginx:   add_header X-Content-Type-Options nosniff always;\n"
        "  Apache:  Header always set X-Content-Type-Options nosniff\n"
        "  Express: app.use(helmet.noSniff())",
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options",
    ),
    (
        "x-frame-options",
        "medium",
        "Without X-Frame-Options, the site can be embedded in iframes by any domain, "
        "enabling clickjacking attacks where users unknowingly click hidden elements.",
        "[FIX] Add header:\n"
        "  X-Frame-Options: DENY (or SAMEORIGIN if framing is needed)\n\n"
        "  Nginx:   add_header X-Frame-Options DENY always;\n"
        "  Apache:  Header always set X-Frame-Options DENY\n\n"
        "[NOTE] CSP frame-ancestors directive is the modern replacement:\n"
        "  Content-Security-Policy: frame-ancestors 'none'",
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options",
    ),
    (
        "referrer-policy",
        "low",
        "Without Referrer-Policy, the browser sends the full URL (including query parameters "
        "with session tokens, search terms, etc.) as the Referer header to external sites.",
        "[FIX] Add header:\n"
        "  Referrer-Policy: strict-origin-when-cross-origin\n\n"
        "  Options (from most to least restrictive):\n"
        "  - no-referrer: never send referrer\n"
        "  - strict-origin-when-cross-origin: recommended default\n"
        "  - same-origin: only send to same origin",
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy",
    ),
    (
        "permissions-policy",
        "low",
        "Permissions-Policy (formerly Feature-Policy) controls which browser features "
        "the site can use (camera, microphone, geolocation, payment). Without it, "
        "embedded content can access all browser APIs.",
        "[FIX] Add header:\n"
        "  Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()\n\n"
        "  Nginx:   add_header Permissions-Policy \"camera=(), microphone=(), geolocation=()\" always;\n"
        "  Apache:  Header always set Permissions-Policy \"camera=(), microphone=(), geolocation=()\"\n\n"
        "[NOTE] Empty () means deny for all origins. (self) allows same-origin only.",
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy",
    ),
    (
        "x-xss-protection",
        "info",
        "X-XSS-Protection is deprecated in modern browsers (CSP is the replacement), "
        "but some older browsers still support it. Setting it to '0' or omitting it "
        "means older browsers won't activate their XSS filter.",
        "[FIX] Add header for legacy browser support:\n"
        "  X-XSS-Protection: 0\n\n"
        "[NOTE] Modern approach: use Content-Security-Policy instead.\n"
        "Setting X-XSS-Protection: 1; mode=block can actually introduce vulnerabilities "
        "in some older browsers. Best practice is now '0' with a strong CSP.",
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection",
    ),
]

# ── CORS misconfigurations to check ─────────────────────────────────────
_CORS_CHECKS = [
    {
        "name": "CORS allows any origin",
        "header": "access-control-allow-origin",
        "bad_values": ["*"],
        "severity": "high",
        "description": (
            "The server returns Access-Control-Allow-Origin: * which allows any website "
            "to read responses. If the API returns sensitive data, any malicious site can "
            "steal it via cross-origin requests."
        ),
        "remediation": (
            "[FIX] Restrict CORS to specific trusted origins:\n"
            "  Access-Control-Allow-Origin: https://yourapp.com\n\n"
            "[AVOID] Never use * with credentials:\n"
            "  Access-Control-Allow-Credentials: true + Allow-Origin: * is blocked by browsers\n"
            "  But reflecting the Origin header without validation is equally dangerous."
        ),
    },
    {
        "name": "CORS allows credentials with permissive origin",
        "header": "access-control-allow-credentials",
        "requires_also": "access-control-allow-origin",
        "severity": "high",
        "description": (
            "The server allows credentials (cookies, auth headers) in cross-origin requests "
            "while also allowing a broad origin. This means a malicious site can make "
            "authenticated requests on behalf of the user."
        ),
        "remediation": (
            "[FIX] When using Allow-Credentials: true:\n"
            "1. NEVER reflect the Origin header without validation\n"
            "2. Maintain a strict whitelist of allowed origins\n"
            "3. Validate the Origin against your whitelist server-side"
        ),
    },
]


async def _fetch_headers(url: str, timeout: float = 8.0) -> tuple[int, dict]:
    """Fetch URL and return (status, headers_dict)."""
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"

    try:
        if parsed.scheme == "https":
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ssl_ctx), timeout=timeout
            )
        else:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout
            )

        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: VulnScan/2.1\r\n"
            f"Accept: */*\r\n"
            f"Connection: close\r\n\r\n"
        )
        writer.write(request.encode())
        await writer.drain()

        response = await asyncio.wait_for(reader.read(16384), timeout=timeout)
        writer.close()

        text = response.decode("utf-8", errors="ignore")
        header_block = text.split("\r\n\r\n", 1)[0]

        status_match = re.match(r"HTTP/\d\.\d\s+(\d+)", header_block)
        status = int(status_match.group(1)) if status_match else 0

        headers = {}
        for line in header_block.split("\r\n")[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()

        return status, headers
    except Exception:
        return 0, {}


async def _fetch_cors_test(url: str, origin: str, timeout: float = 8.0) -> tuple[int, dict]:
    """Send request with Origin header to test CORS."""
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"

    try:
        if parsed.scheme == "https":
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ssl_ctx), timeout=timeout
            )
        else:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout
            )

        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Origin: {origin}\r\n"
            f"User-Agent: VulnScan/2.1\r\n"
            f"Accept: */*\r\n"
            f"Connection: close\r\n\r\n"
        )
        writer.write(request.encode())
        await writer.drain()

        response = await asyncio.wait_for(reader.read(16384), timeout=timeout)
        writer.close()

        text = response.decode("utf-8", errors="ignore")
        header_block = text.split("\r\n\r\n", 1)[0]

        status_match = re.match(r"HTTP/\d\.\d\s+(\d+)", header_block)
        status = int(status_match.group(1)) if status_match else 0

        headers = {}
        for line in header_block.split("\r\n")[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()

        return status, headers
    except Exception:
        return 0, {}


class Check(Plugin):
    async def run(self, target: str, ctx) -> PluginResult:
        ports = ctx.get("net.open_ports", []) or []
        http_data = (ctx.get("fingerprint.http", {}) or {}).get("http", [])
        target_raw = ctx.get("target_raw", target)
        findings = []
        header_results = {"present": [], "missing": [], "misconfigured": []}

        # ── Determine URLs to check ────────────────────────────────────
        urls_to_check = []
        if re.match(r"^https?://", target_raw, re.I):
            urls_to_check.append(target_raw.rstrip("/") + "/")
        else:
            for item in http_data:
                url = item.get("url", "")
                if url:
                    urls_to_check.append(url.rstrip("/") + "/")
            if not urls_to_check:
                web_ports = [p for p in ports if p in (80, 443, 8080, 8443, 3000, 5000, 8000)]
                for p in web_ports:
                    scheme = "https" if p in (443, 8443) else "http"
                    urls_to_check.append(f"{scheme}://{target}:{p}/")

        if not urls_to_check:
            return PluginResult(artifacts={"web.security_headers": header_results})

        # ── Fetch headers from each URL ────────────────────────────────
        for url in urls_to_check[:3]:
            status, headers = await _fetch_headers(url)
            if status == 0:
                continue

            is_https = url.startswith("https://")

            # ── Check required security headers ────────────────────────
            for hdr_name, severity, description, remediation, reference in _REQUIRED_HEADERS:
                # HSTS only applies to HTTPS
                if hdr_name == "strict-transport-security" and not is_https:
                    continue

                value = headers.get(hdr_name, "")

                if not value:
                    fp = stable_fingerprint(target, META.plugin_id, "missing", hdr_name, url)
                    findings.append(Finding(
                        severity=severity,
                        plugin_id=META.plugin_id,
                        title=f"Missing security header: {hdr_name.title()}",
                        description=description,
                        evidence=f"url={url} header={hdr_name} status=missing",
                        affected=target,
                        fingerprint=fp,
                        confidence=1.0,
                        remediation=(
                            f"[AFFECTED] {url}\n"
                            f"[MISSING] {hdr_name}\n\n"
                            f"{remediation}\n\n"
                            f"[REFERENCE] {reference}"
                        ),
                        references=[reference],
                    ))
                    header_results["missing"].append(hdr_name)
                else:
                    header_results["present"].append(hdr_name)

                    # ── Validate header values ─────────────────────────
                    if hdr_name == "strict-transport-security":
                        max_age_match = re.search(r"max-age=(\d+)", value)
                        if max_age_match:
                            max_age = int(max_age_match.group(1))
                            if max_age < 15768000:  # Less than 6 months
                                fp = stable_fingerprint(target, META.plugin_id, "weak_hsts", url)
                                findings.append(Finding(
                                    severity="low",
                                    plugin_id=META.plugin_id,
                                    title=f"HSTS max-age is too short: {max_age}s ({max_age // 86400} days)",
                                    description=(
                                        f"HSTS max-age is {max_age} seconds ({max_age // 86400} days). "
                                        f"Recommended minimum is 6 months (15768000s), ideally 1 year (31536000s)."
                                    ),
                                    evidence=f"url={url} hsts={value} max_age={max_age}",
                                    affected=target,
                                    fingerprint=fp,
                                    confidence=1.0,
                                    remediation=(
                                        f"[AFFECTED] HSTS max-age={max_age}s ({max_age // 86400} days)\n\n"
                                        f"[FIX] Increase to at least 1 year:\n"
                                        f"  Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
                                    ),
                                    references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"],
                                ))

                    if hdr_name == "content-security-policy":
                        csp_lower = value.lower()
                        issues = []
                        if "unsafe-inline" in csp_lower and "script-src" in csp_lower:
                            issues.append("'unsafe-inline' in script-src defeats XSS protection")
                        if "unsafe-eval" in csp_lower:
                            issues.append("'unsafe-eval' allows eval() — code injection risk")
                        if re.search(r"(?:default-src|script-src)\s+\*", csp_lower):
                            issues.append("wildcard (*) source allows loading from any domain")

                        if issues:
                            fp = stable_fingerprint(target, META.plugin_id, "weak_csp", url)
                            findings.append(Finding(
                                severity="medium",
                                plugin_id=META.plugin_id,
                                title=f"Weak Content-Security-Policy ({len(issues)} issue(s))",
                                description=(
                                    f"The CSP header at {url} has weaknesses:\n"
                                    + "\n".join(f"  - {i}" for i in issues)
                                ),
                                evidence=f"url={url} csp={value[:200]} issues={issues}",
                                affected=target,
                                fingerprint=fp,
                                confidence=0.95,
                                remediation=(
                                    f"[AFFECTED] Weak CSP at {url}\n"
                                    f"[ISSUES]\n"
                                    + "\n".join(f"  - {i}" for i in issues)
                                    + "\n\n[FIX] Tighten CSP directives:\n"
                                    "  - Replace 'unsafe-inline' with nonce-based or hash-based approach\n"
                                    "  - Remove 'unsafe-eval' and refactor code to avoid eval()\n"
                                    "  - Replace * with specific domain allowlists"
                                ),
                                references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"],
                            ))
                            header_results["misconfigured"].append(hdr_name)

            # ── CORS checks ────────────────────────────────────────────
            # Test with a malicious origin
            evil_origin = "https://evil-attacker.com"
            cors_status, cors_headers = await _fetch_cors_test(url, evil_origin)

            if cors_status > 0:
                acao = cors_headers.get("access-control-allow-origin", "")
                acac = cors_headers.get("access-control-allow-credentials", "")

                # Check 1: Origin reflection (most dangerous)
                if acao == evil_origin:
                    sev = "critical" if acac.lower() == "true" else "high"
                    fp = stable_fingerprint(target, META.plugin_id, "cors_reflect", url)
                    findings.append(Finding(
                        severity=sev,
                        plugin_id=META.plugin_id,
                        title=f"CORS reflects arbitrary Origin{' with credentials' if acac.lower() == 'true' else ''}",
                        description=(
                            f"The server at {url} reflects the attacker's Origin header in "
                            f"Access-Control-Allow-Origin. "
                            + ("Combined with Allow-Credentials: true, this allows any website to "
                               "make authenticated requests and read responses — effectively bypassing "
                               "same-origin policy completely." if acac.lower() == "true"
                               else "Any website can read API responses from this server.")
                        ),
                        evidence=f"url={url} origin={evil_origin} acao={acao} acac={acac}",
                        affected=target,
                        fingerprint=fp,
                        confidence=0.98,
                        remediation=(
                            f"[CRITICAL] Server reflects arbitrary Origin header\n"
                            f"  Tested with: {evil_origin}\n"
                            f"  Returned: Access-Control-Allow-Origin: {acao}\n"
                            f"  Credentials: {acac}\n\n"
                            f"[FIX]\n"
                            f"1. Maintain a strict whitelist of allowed origins\n"
                            f"2. Validate Origin header server-side before reflecting\n"
                            f"3. NEVER reflect Origin directly — check against whitelist first\n"
                            f"4. Use framework-level CORS configuration\n\n"
                            f"[EXAMPLE - Express.js]\n"
                            f"  const allowedOrigins = ['https://myapp.com'];\n"
                            f"  app.use(cors({{ origin: allowedOrigins, credentials: true }}));"
                        ),
                        references=["https://portswigger.net/web-security/cors"],
                    ))

                # Check 2: Wildcard origin
                elif acao == "*":
                    fp = stable_fingerprint(target, META.plugin_id, "cors_wildcard", url)
                    findings.append(Finding(
                        severity="medium",
                        plugin_id=META.plugin_id,
                        title=f"CORS uses wildcard origin (*)",
                        description=(
                            f"The server at {url} returns Access-Control-Allow-Origin: * "
                            f"which allows any website to read responses. If the API returns "
                            f"any user-specific or sensitive data, this is a security risk."
                        ),
                        evidence=f"url={url} acao=* acac={acac}",
                        affected=target,
                        fingerprint=fp,
                        confidence=1.0,
                        remediation=(
                            f"[AFFECTED] CORS wildcard at {url}\n\n"
                            f"[FIX] Replace * with specific allowed origins:\n"
                            f"  Access-Control-Allow-Origin: https://yourapp.com\n\n"
                            f"[NOTE] Wildcard (*) is acceptable ONLY for truly public APIs "
                            f"that serve no user-specific data (e.g., public CDNs, open data APIs)."
                        ),
                        references=["https://portswigger.net/web-security/cors"],
                    ))

            # ── Check for cookie security flags ────────────────────────
            set_cookie = headers.get("set-cookie", "")
            if set_cookie:
                cookie_issues = []
                if "secure" not in set_cookie.lower() and is_https:
                    cookie_issues.append("Missing 'Secure' flag — cookie sent over HTTP too")
                if "httponly" not in set_cookie.lower():
                    cookie_issues.append("Missing 'HttpOnly' flag — cookie accessible via JavaScript (XSS risk)")
                if "samesite" not in set_cookie.lower():
                    cookie_issues.append("Missing 'SameSite' attribute — vulnerable to CSRF")

                if cookie_issues:
                    fp = stable_fingerprint(target, META.plugin_id, "cookie_flags", url)
                    findings.append(Finding(
                        severity="medium",
                        plugin_id=META.plugin_id,
                        title=f"Cookie missing security flags ({len(cookie_issues)} issue(s))",
                        description=(
                            f"Cookies set by {url} are missing security attributes:\n"
                            + "\n".join(f"  - {i}" for i in cookie_issues)
                        ),
                        evidence=f"url={url} set-cookie={set_cookie[:200]} issues={len(cookie_issues)}",
                        affected=target,
                        fingerprint=fp,
                        confidence=0.95,
                        remediation=(
                            f"[AFFECTED] Cookie security flags at {url}\n"
                            f"[ISSUES]\n"
                            + "\n".join(f"  - {i}" for i in cookie_issues)
                            + "\n\n[FIX] Set all security flags:\n"
                            "  Set-Cookie: session=abc; Secure; HttpOnly; SameSite=Lax; Path=/\n\n"
                            "  Express: app.use(session({ cookie: { secure: true, httpOnly: true, sameSite: 'lax' } }))\n"
                            "  Django:  SESSION_COOKIE_SECURE=True; SESSION_COOKIE_HTTPONLY=True; SESSION_COOKIE_SAMESITE='Lax'"
                        ),
                        references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies"],
                    ))

        # ── Build score summary ────────────────────────────────────────
        total_headers = len(_REQUIRED_HEADERS)
        present_count = len(set(header_results["present"]))
        missing_count = len(set(header_results["missing"]))

        if present_count + missing_count > 0:
            score = round(present_count / (present_count + missing_count) * 100)
            grade = "A" if score >= 90 else "B" if score >= 70 else "C" if score >= 50 else "D" if score >= 30 else "F"

            fp = stable_fingerprint(target, META.plugin_id, "score_summary")
            findings.append(Finding(
                severity="info",
                plugin_id=META.plugin_id,
                title=f"Security Headers Score: {grade} ({score}%) — {present_count}/{present_count + missing_count} headers present",
                description=(
                    f"Security headers audit summary:\n"
                    f"  Present: {', '.join(sorted(set(header_results['present']))) or 'none'}\n"
                    f"  Missing: {', '.join(sorted(set(header_results['missing']))) or 'none'}\n"
                    f"  Misconfigured: {', '.join(sorted(set(header_results['misconfigured']))) or 'none'}"
                ),
                evidence=f"score={score} grade={grade} present={present_count} missing={missing_count}",
                affected=target,
                fingerprint=fp,
                confidence=1.0,
                remediation=(
                    f"[SCORE] {grade} ({score}%)\n\n"
                    f"[TEST YOUR HEADERS] https://securityheaders.com/?q={urllib.parse.quote(urls_to_check[0])}\n\n"
                    f"[QUICK WIN] Use helmet.js (Node.js) or django-secure to add all headers at once."
                ),
                references=["https://securityheaders.com/"],
            ))

        header_results["score"] = score if (present_count + missing_count) > 0 else 0

        return PluginResult(
            findings=findings,
            artifacts={"web.security_headers": header_results},
        )

