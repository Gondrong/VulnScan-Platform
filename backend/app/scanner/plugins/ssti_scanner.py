"""
Server-Side Template Injection (SSTI) Scanner — checks for template
injection vulnerabilities in web applications.

Tests for SSTI across multiple template engines:
  - Jinja2 / Twig (Python/PHP): {{7*7}} → 49
  - Mako (Python): ${7*7} → 49
  - Freemarker (Java): ${7*7} → 49
  - Smarty (PHP): {7*7} → 49
  - ERB (Ruby): <%= 7*7 %> → 49
  - Pebble (Java): {{7*7}} → 49
  - Thymeleaf (Java): [[${7*7}]] → 49
  - Velocity (Java): #set($x=7*7)${x} → 49

Uses mathematical expression evaluation as proof — if {{7*7}} returns "49",
the template engine is evaluating server-side expressions.

All payloads are benign (arithmetic only). No code execution, no file access.
"""
import asyncio
import logging
import re
import ssl
import urllib.parse

from app.scanner.plugins.base import Finding, Plugin, PluginMeta, PluginResult
from app.scanner.context import stable_fingerprint

logger = logging.getLogger("vulnscan.ssti")

META = PluginMeta(
    plugin_id="web.ssti.scanner",
    name="SSTI (Server-Side Template Injection) Scanner",
    category="web",
    depends_on=["fingerprint.http"],
    consumes=["fingerprint.http", "net.open_ports"],
    provides=["web.ssti.findings"],
    enabled_by_default=True,
    timeout_seconds=30.0,
)

# SSTI payloads: (raw_payload, url_encoded_payload, expected_output, engine_hint)
_PAYLOADS = [
    # Jinja2 / Twig / Pebble
    ("{{7*7}}", "%7B%7B7*7%7D%7D", "49", "Jinja2/Twig/Pebble"),
    ("{{7*'7'}}", "%7B%7B7*'7'%7D%7D", "7777777", "Jinja2 (Python)"),
    # Mako / Freemarker / EL
    ("${7*7}", "%24%7B7*7%7D", "49", "Mako/Freemarker/EL"),
    # Smarty
    ("{7*7}", "%7B7*7%7D", "49", "Smarty"),
    # ERB (Ruby)
    ("<%= 7*7 %>", "%3C%25%3D%207*7%20%25%3E", "49", "ERB (Ruby)"),
    # Thymeleaf
    ("[[${7*7}]]", "%5B%5B%24%7B7*7%7D%5D%5D", "49", "Thymeleaf"),
    # Velocity
    ("#set($x=7*7)${x}", "%23set(%24x%3D7*7)%24%7Bx%7D", "49", "Velocity"),
    # Pug/Jade (Node.js)
    ("#{7*7}", "%23%7B7*7%7D", "49", "Pug/Jade"),
    # Nunjucks (Node.js)
    ("{{range.constructor(\"return 7*7\")()}}", None, "49", "Nunjucks"),
]

# Injection points to test
_TEST_PARAMS = [
    "name", "q", "search", "query", "user", "username", "email",
    "template", "page", "view", "lang", "locale", "message", "msg",
    "title", "text", "content", "input", "value", "data", "id",
]

# Paths with parameters to test
_TEST_PATHS = [
    "/?{param}={payload}",
    "/search?{param}={payload}",
    "/api/v1/render?{param}={payload}",
]


async def _http_get(host: str, port: int, path: str, scheme: str,
                    timeout: float = 5.0) -> tuple[int, str]:
    """Send HTTP GET, return (status, body)."""
    try:
        if scheme == "https":
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
            f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
            f"Accept: text/html,*/*\r\n"
            f"Connection: close\r\n\r\n"
        )
        writer.write(request.encode())
        await writer.drain()
        data = await asyncio.wait_for(reader.read(32768), timeout=timeout)
        writer.close()

        text = data.decode("utf-8", errors="ignore")
        parts = text.split("\r\n\r\n", 1)
        header_block = parts[0] if parts else ""
        body = parts[1] if len(parts) > 1 else ""

        status_match = re.match(r"HTTP/\d\.\d\s+(\d+)", header_block)
        status = int(status_match.group(1)) if status_match else 0

        return status, body
    except Exception:
        return 0, ""


async def _http_post(host: str, port: int, path: str, scheme: str,
                     form_data: str, timeout: float = 5.0) -> tuple[int, str]:
    """Send HTTP POST with form data, return (status, body)."""
    try:
        if scheme == "https":
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
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: Mozilla/5.0\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: {len(form_data)}\r\n"
            f"Connection: close\r\n\r\n"
            f"{form_data}"
        )
        writer.write(request.encode())
        await writer.drain()
        data = await asyncio.wait_for(reader.read(32768), timeout=timeout)
        writer.close()

        text = data.decode("utf-8", errors="ignore")
        parts = text.split("\r\n\r\n", 1)
        header_block = parts[0] if parts else ""
        body = parts[1] if len(parts) > 1 else ""

        status_match = re.match(r"HTTP/\d\.\d\s+(\d+)", header_block)
        status = int(status_match.group(1)) if status_match else 0

        return status, body
    except Exception:
        return 0, ""


def _check_ssti_in_response(body: str, expected: str, raw_payload: str) -> bool:
    """Check if SSTI result appears in response but not the raw payload."""
    if not body:
        return False
    # The expected result (e.g., "49") must appear in the body
    if expected not in body:
        return False
    # The raw payload should NOT appear literally (it was evaluated, not echoed)
    # Exception: if expected is inside the payload (e.g., "49" appears in "{{49}}")
    if raw_payload in body:
        return False
    return True


class Check(Plugin):
    async def run(self, target: str, ctx) -> PluginResult:
        ports = ctx.get("net.open_ports", []) or []
        http_data = (ctx.get("fingerprint.http", {}) or {}).get("http", [])
        target_raw = ctx.get("target_raw", target)
        findings: list[Finding] = []

        # Build URL list
        urls = []
        if re.match(r"^https?://", target_raw, re.I):
            urls.append(target_raw.rstrip("/"))
        else:
            for item in http_data:
                url = item.get("url", "")
                if url:
                    urls.append(url.rstrip("/"))
            if not urls:
                web_ports = [p for p in ports if p in (80, 443, 8080, 8443, 3000, 5000, 8000)]
                for p in web_ports:
                    scheme = "https" if p in (443, 8443) else "http"
                    urls.append(f"{scheme}://{target}:{p}")

        if not urls:
            return PluginResult(artifacts={"web.ssti.findings": 0})

        found_vulns = set()  # (base_url, engine) dedup

        for base_url in urls[:2]:
            parsed = urllib.parse.urlparse(base_url)
            host = parsed.hostname or target
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            scheme = parsed.scheme

            # First get baseline to check if the site is responding
            baseline_status, baseline_body = await _http_get(
                host, port, "/", scheme
            )
            if baseline_status == 0:
                continue

            # Test GET parameters
            for param in _TEST_PARAMS[:8]:  # Limit params for speed
                for raw_payload, encoded_payload, expected, engine in _PAYLOADS:
                    if encoded_payload is None:
                        encoded_payload = urllib.parse.quote(raw_payload)

                    # Test in URL query parameter
                    test_path = f"/?{param}={encoded_payload}"
                    status, body = await _http_get(host, port, test_path, scheme)

                    if status > 0 and _check_ssti_in_response(body, expected, raw_payload):
                        vuln_key = (base_url, engine)
                        if vuln_key in found_vulns:
                            continue
                        found_vulns.add(vuln_key)

                        fp = stable_fingerprint(
                            target, META.plugin_id, engine, param, base_url
                        )
                        findings.append(Finding(
                            severity="critical",
                            plugin_id=META.plugin_id,
                            title=(
                                f"SSTI detected — {engine} template injection "
                                f"via '{param}' parameter"
                            ),
                            description=(
                                f"Server-Side Template Injection (SSTI) confirmed at "
                                f"{base_url}/?{param}=... using {engine} template syntax. "
                                f"The payload {raw_payload} was evaluated server-side, "
                                f"returning '{expected}' in the response. "
                                f"SSTI can lead to Remote Code Execution (RCE), "
                                f"allowing an attacker to execute arbitrary commands "
                                f"on the server, read files, and pivot to internal systems."
                            ),
                            evidence=(
                                f"url={base_url} param={param} method=GET "
                                f"payload={raw_payload} expected={expected} "
                                f"engine={engine} status={status} "
                                f"body_sample={body[:300]}"
                            ),
                            affected=target,
                            fingerprint=fp,
                            confidence=0.95,
                            cvss=9.8,
                            remediation=(
                                f"[CRITICAL — Server-Side Template Injection ({engine})]\n\n"
                                f"Parameter: {param}\n"
                                f"Payload: {raw_payload} → {expected}\n\n"
                                "SSTI allows Remote Code Execution on the server.\n\n"
                                "Remediation:\n"
                                "1. NEVER pass user input directly into template rendering:\n"
                                "   BAD:  render_template_string(user_input)\n"
                                "   GOOD: render_template('page.html', name=user_input)\n"
                                "2. Use a logic-less template engine (Mustache, Handlebars)\n"
                                "3. Sandbox the template engine:\n"
                                "   - Jinja2: SandboxedEnvironment()\n"
                                "   - Freemarker: Configuration.setNewBuiltinClassResolver(SAFER)\n"
                                "4. Validate/sanitize input before template rendering\n"
                                "5. Use Content-Security-Policy headers\n"
                                "6. Implement WAF rules to block template syntax in parameters\n\n"
                                "References:\n"
                                "- https://portswigger.net/web-security/server-side-template-injection"
                            ),
                            references=[
                                "https://portswigger.net/web-security/server-side-template-injection",
                                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server-side_Template_Injection",
                                "https://cwe.mitre.org/data/definitions/1336.html",
                            ],
                        ))
                        break  # Found SSTI for this engine, skip remaining payloads

                    await asyncio.sleep(0.02)

                if found_vulns:
                    break  # Found SSTI, skip remaining params

            # Test POST parameters for common form endpoints
            if not found_vulns:
                post_paths = ["/", "/search", "/contact", "/api/render"]
                for post_path in post_paths:
                    for param in _TEST_PARAMS[:5]:
                        for raw_payload, encoded_payload, expected, engine in _PAYLOADS[:4]:
                            form_data = f"{param}={urllib.parse.quote(raw_payload)}"
                            status, body = await _http_post(
                                host, port, post_path, scheme, form_data
                            )
                            if status > 0 and _check_ssti_in_response(body, expected, raw_payload):
                                vuln_key = (base_url, engine, "POST")
                                if vuln_key in found_vulns:
                                    continue
                                found_vulns.add(vuln_key)

                                fp = stable_fingerprint(
                                    target, META.plugin_id, engine, param,
                                    post_path, "POST"
                                )
                                findings.append(Finding(
                                    severity="critical",
                                    plugin_id=META.plugin_id,
                                    title=(
                                        f"SSTI detected (POST) — {engine} "
                                        f"via '{param}' at {post_path}"
                                    ),
                                    description=(
                                        f"SSTI confirmed via POST to {base_url}{post_path} "
                                        f"in the '{param}' parameter using {engine} syntax. "
                                        f"Payload: {raw_payload} → {expected}. "
                                        f"This leads to Remote Code Execution."
                                    ),
                                    evidence=(
                                        f"url={base_url}{post_path} param={param} "
                                        f"method=POST payload={raw_payload} "
                                        f"expected={expected} engine={engine}"
                                    ),
                                    affected=target,
                                    fingerprint=fp,
                                    confidence=0.95,
                                    cvss=9.8,
                                    remediation=(
                                        f"[CRITICAL — SSTI via POST ({engine})]\n\n"
                                        "Never use user input in template rendering.\n"
                                        "Use parameterized templates instead."
                                    ),
                                    references=[
                                        "https://portswigger.net/web-security/server-side-template-injection",
                                        "https://cwe.mitre.org/data/definitions/1336.html",
                                    ],
                                ))

                            await asyncio.sleep(0.02)

            # Check for template error disclosure (even without successful injection)
            if not found_vulns:
                error_payloads = [
                    ("{{", "Jinja2/Twig"),
                    ("${", "Freemarker/Mako"),
                    ("<%= %>", "ERB"),
                    ("#{}", "Pug"),
                ]
                for err_payload, err_engine in error_payloads:
                    encoded = urllib.parse.quote(err_payload)
                    status, body = await _http_get(
                        host, port, f"/?q={encoded}", scheme
                    )
                    if status >= 400 and body:
                        body_lower = body.lower()
                        error_indicators = [
                            "templateerror", "template error", "jinja2",
                            "twig", "freemarker", "mako", "erb", "pug",
                            "smarty", "thymeleaf", "velocity", "nunjucks",
                            "templatenotfound", "templatesyntaxerror",
                            "undefinederror", "unexpected tag",
                        ]
                        for indicator in error_indicators:
                            if indicator in body_lower:
                                fp = stable_fingerprint(
                                    target, META.plugin_id, "error_disclosure",
                                    indicator, base_url
                                )
                                findings.append(Finding(
                                    severity="medium",
                                    plugin_id=META.plugin_id,
                                    title=(
                                        f"Template engine error disclosed — "
                                        f"potential SSTI ({err_engine})"
                                    ),
                                    description=(
                                        f"The application at {base_url} returns template "
                                        f"engine error messages when given malformed template "
                                        f"syntax ({err_payload}). This confirms a template "
                                        f"engine is processing user input and may be "
                                        f"exploitable for SSTI. Error indicator: '{indicator}'."
                                    ),
                                    evidence=(
                                        f"url={base_url}/?q={encoded} "
                                        f"payload={err_payload} engine_hint={err_engine} "
                                        f"error_indicator={indicator} status={status}"
                                    ),
                                    affected=target,
                                    fingerprint=fp,
                                    confidence=0.70,
                                    remediation=(
                                        "[MEDIUM — Template Engine Error Disclosure]\n\n"
                                        "The application leaks template engine details in errors.\n\n"
                                        "1. Disable debug mode in production\n"
                                        "2. Use custom error pages (don't expose stack traces)\n"
                                        "3. Ensure user input is never passed to template rendering\n"
                                        "4. Review all template rendering code for SSTI"
                                    ),
                                    references=[
                                        "https://portswigger.net/web-security/server-side-template-injection",
                                    ],
                                ))
                                break

        return PluginResult(
            findings=findings,
            artifacts={"web.ssti.findings": len(findings)},
        )
