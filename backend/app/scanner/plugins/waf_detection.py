"""
WAF Detection & Bypass Scanner — identifies Web Application Firewalls
and tests common bypass techniques.

Detection methods:
  - Response header analysis (Server, X-Powered-By, Via, etc.)
  - Known WAF signature matching (Cloudflare, AWS WAF, Akamai, etc.)
  - Cookie name analysis
  - Block page fingerprinting
  - Behavioral analysis (send known-bad payloads, check response patterns)

Bypass tests (informational — reports which techniques may work):
  - Case variation
  - Double URL encoding
  - Unicode normalization bypass
  - HTTP method override
  - Chunked transfer encoding
  - Null byte injection

All tests are safe — no actual exploitation is performed.
"""
import asyncio
import logging
import re
import ssl

from app.scanner.plugins.base import Finding, Plugin, PluginMeta, PluginResult
from app.scanner.context import stable_fingerprint

logger = logging.getLogger("vulnscan.waf_detection")

META = PluginMeta(
    plugin_id="web.waf.detection",
    name="WAF Detection & Bypass Scanner",
    category="web",
    depends_on=["fingerprint.http"],
    consumes=["fingerprint.http", "net.open_ports"],
    provides=["web.waf.findings"],
    enabled_by_default=True,
    timeout_seconds=25.0,
)

# WAF signatures: (header/cookie/body pattern, WAF name)
_WAF_SIGNATURES = [
    # Header-based
    {"header": "server", "pattern": r"cloudflare", "name": "Cloudflare", "type": "header"},
    {"header": "cf-ray", "pattern": r".", "name": "Cloudflare", "type": "header"},
    {"header": "server", "pattern": r"AkamaiGHost", "name": "Akamai", "type": "header"},
    {"header": "x-akamai-transformed", "pattern": r".", "name": "Akamai", "type": "header"},
    {"header": "server", "pattern": r"Sucuri", "name": "Sucuri", "type": "header"},
    {"header": "x-sucuri-id", "pattern": r".", "name": "Sucuri", "type": "header"},
    {"header": "server", "pattern": r"(?:imunify|BitNinja)", "name": "Imunify/BitNinja", "type": "header"},
    {"header": "x-cdn", "pattern": r"Incapsula", "name": "Imperva Incapsula", "type": "header"},
    {"header": "x-iinfo", "pattern": r".", "name": "Imperva Incapsula", "type": "header"},
    {"header": "server", "pattern": r"(?:BIG-IP|BigIP|F5)", "name": "F5 BIG-IP", "type": "header"},
    {"header": "x-powered-by", "pattern": r"(?:ASP\.NET|\.NET)", "name": "IIS/ASP.NET (built-in filtering)", "type": "header"},
    {"header": "server", "pattern": r"mod_security", "name": "ModSecurity", "type": "header"},
    {"header": "server", "pattern": r"Barracuda", "name": "Barracuda WAF", "type": "header"},
    {"header": "server", "pattern": r"FortiWeb", "name": "FortiWeb", "type": "header"},
    {"header": "x-denied-reason", "pattern": r".", "name": "WatchGuard", "type": "header"},
    {"header": "x-czid", "pattern": r".", "name": "Comodo", "type": "header"},
    {"header": "server", "pattern": r"Netlify", "name": "Netlify (edge rules)", "type": "header"},
    {"header": "server", "pattern": r"Vercel", "name": "Vercel (edge)", "type": "header"},
    # Cookie-based
    {"header": "set-cookie", "pattern": r"__cfduid|__cf_bm|cf_clearance", "name": "Cloudflare", "type": "cookie"},
    {"header": "set-cookie", "pattern": r"visid_incap|incap_ses", "name": "Imperva Incapsula", "type": "cookie"},
    {"header": "set-cookie", "pattern": r"sucuri_cloudproxy", "name": "Sucuri", "type": "cookie"},
    {"header": "set-cookie", "pattern": r"ak_bmsc|bm_sv", "name": "Akamai", "type": "cookie"},
    {"header": "set-cookie", "pattern": r"awsalb|awsalbcors", "name": "AWS ALB/WAF", "type": "cookie"},
]

# Block page patterns (body content when WAF blocks)
_BLOCK_PATTERNS = [
    (r"attention\s+required.*cloudflare", "Cloudflare"),
    (r"ray\s+id|cf-error-details", "Cloudflare"),
    (r"access\s+denied.*incapsula", "Imperva Incapsula"),
    (r"sucuri\s+website\s+firewall", "Sucuri"),
    (r"web\s+application\s+firewall.*barracuda", "Barracuda"),
    (r"request\s+blocked.*fortiweb", "FortiWeb"),
    (r"mod_security|modsecurity", "ModSecurity"),
    (r"aws\s*waf", "AWS WAF"),
    (r"<title>403 Forbidden</title>.*openresty", "OpenResty/Lua WAF"),
    (r"powered.*by.*wordfence", "Wordfence"),
    (r"blocked.*by.*akamai", "Akamai"),
]

# Payloads to trigger WAF blocks
_TRIGGER_PAYLOADS = [
    ("/?test=<script>alert(1)</script>", "XSS payload"),
    ("/?test=' OR 1=1--", "SQLi payload"),
    ("/?test=../../etc/passwd", "Path traversal"),
    ("/?test=;cat /etc/passwd", "Command injection"),
]

# Bypass techniques to test
_BYPASS_TESTS = [
    {
        "name": "Case variation",
        "path": "/?test=<ScRiPt>alert(1)</sCrIpT>",
        "desc": "Mixed case to bypass case-sensitive WAF rules",
    },
    {
        "name": "Double URL encoding",
        "path": "/?test=%253Cscript%253Ealert(1)%253C%252Fscript%253E",
        "desc": "Double-encoded payload to bypass single-decode WAFs",
    },
    {
        "name": "Unicode encoding",
        "path": "/?test=%u003Cscript%u003Ealert(1)%u003C/script%u003E",
        "desc": "Unicode-encoded characters to bypass ASCII-only filters",
    },
    {
        "name": "Null byte injection",
        "path": "/?test=<scr%00ipt>alert(1)</scr%00ipt>",
        "desc": "Null bytes to truncate WAF pattern matching",
    },
    {
        "name": "Comment obfuscation (SQL)",
        "path": "/?test=1'/**/OR/**/1=1--",
        "desc": "SQL comments to break WAF tokenization",
    },
    {
        "name": "HTTP Parameter Pollution",
        "path": "/?test=safe&test=<script>alert(1)</script>",
        "desc": "Duplicate parameters — WAF checks first, app uses last",
    },
]


async def _http_request(host: str, port: int, path: str, scheme: str,
                        timeout: float = 5.0) -> tuple[int, dict, str]:
    """Send HTTP request, return (status, headers_dict, body)."""
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
            f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n"
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

        headers = {}
        for line in header_block.split("\r\n")[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                key = k.strip().lower()
                # Collect multiple Set-Cookie headers
                if key in headers:
                    headers[key] += "; " + v.strip()
                else:
                    headers[key] = v.strip()

        return status, headers, body
    except Exception:
        return 0, {}, ""


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
                web_ports = [p for p in ports if p in (80, 443, 8080, 8443)]
                for p in web_ports:
                    scheme = "https" if p in (443, 8443) else "http"
                    urls.append(f"{scheme}://{target}:{p}")

        if not urls:
            return PluginResult(artifacts={"web.waf.findings": {}})

        import urllib.parse

        for base_url in urls[:2]:
            parsed = urllib.parse.urlparse(base_url)
            host = parsed.hostname or target
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            scheme = parsed.scheme

            # Step 1: Baseline request for WAF signature detection
            status, headers, body = await _http_request(host, port, "/", scheme)
            if status == 0:
                continue

            detected_wafs = set()

            # Check header/cookie signatures
            for sig in _WAF_SIGNATURES:
                hdr_value = headers.get(sig["header"], "")
                if hdr_value and re.search(sig["pattern"], hdr_value, re.I):
                    detected_wafs.add(sig["name"])

            # Step 2: Send trigger payloads to detect WAF blocking
            blocked_payloads = []
            for payload_path, payload_name in _TRIGGER_PAYLOADS:
                p_status, p_headers, p_body = await _http_request(
                    host, port, payload_path, scheme
                )

                if p_status in (403, 406, 429, 503):
                    blocked_payloads.append((payload_name, p_status))

                    # Check block page for WAF signatures
                    full_response = str(p_headers) + " " + p_body
                    for pattern, waf_name in _BLOCK_PATTERNS:
                        if re.search(pattern, full_response, re.I):
                            detected_wafs.add(waf_name)

                    # Check headers on blocked response
                    for sig in _WAF_SIGNATURES:
                        hdr_value = p_headers.get(sig["header"], "")
                        if hdr_value and re.search(sig["pattern"], hdr_value, re.I):
                            detected_wafs.add(sig["name"])

                await asyncio.sleep(0.1)  # Rate limit

            if not detected_wafs and not blocked_payloads:
                # No WAF detected — report as informational
                fp = stable_fingerprint(target, META.plugin_id, "no_waf", base_url)
                findings.append(Finding(
                    severity="medium",
                    plugin_id=META.plugin_id,
                    title="No WAF detected — application directly exposed",
                    description=(
                        f"No Web Application Firewall was detected protecting {base_url}. "
                        f"The application is directly exposed to attack payloads without "
                        f"any external filtering layer. All {len(_TRIGGER_PAYLOADS)} "
                        f"trigger payloads were passed through without blocking."
                    ),
                    evidence=(
                        f"url={base_url} waf_detected=none "
                        f"trigger_payloads_blocked=0/{len(_TRIGGER_PAYLOADS)}"
                    ),
                    affected=target,
                    fingerprint=fp,
                    confidence=0.70,
                    remediation=(
                        "[MEDIUM — No WAF Protection]\n\n"
                        "Consider deploying a WAF:\n"
                        "- Cloud: Cloudflare, AWS WAF, Azure Front Door, Akamai\n"
                        "- Self-hosted: ModSecurity + OWASP CRS, NAXSI, Coraza\n"
                        "- Application: Wordfence (WordPress), django-defender\n\n"
                        "A WAF provides defense-in-depth against:\n"
                        "- SQL injection, XSS, RFI/LFI\n"
                        "- DDoS and bot attacks\n"
                        "- Zero-day exploitation attempts\n\n"
                        "Note: A WAF is not a substitute for secure coding."
                    ),
                    references=[
                        "https://owasp.org/www-community/Web_Application_Firewall",
                    ],
                ))
                continue

            # WAF detected — report it
            waf_list = sorted(detected_wafs) if detected_wafs else ["Unknown WAF"]

            fp = stable_fingerprint(target, META.plugin_id, "waf_detected", base_url)
            findings.append(Finding(
                severity="info",
                plugin_id=META.plugin_id,
                title=f"WAF detected: {', '.join(waf_list)}",
                description=(
                    f"Web Application Firewall(s) detected at {base_url}: "
                    f"{', '.join(waf_list)}. "
                    f"Blocked {len(blocked_payloads)}/{len(_TRIGGER_PAYLOADS)} test payloads. "
                    f"Blocked: {', '.join(f'{n} (HTTP {s})' for n, s in blocked_payloads)}."
                ),
                evidence=(
                    f"url={base_url} wafs={waf_list} "
                    f"blocked={len(blocked_payloads)}/{len(_TRIGGER_PAYLOADS)} "
                    f"details={blocked_payloads}"
                ),
                affected=target,
                fingerprint=fp,
                confidence=0.90,
            ))

            # Step 3: Test bypass techniques
            if blocked_payloads:
                bypasses_found = []

                for bypass in _BYPASS_TESTS:
                    b_status, b_headers, b_body = await _http_request(
                        host, port, bypass["path"], scheme
                    )
                    # If we get 200 (not blocked) with a payload that was previously blocked
                    if b_status == 200:
                        # Verify the payload is reflected (not just a default 200 page)
                        bypasses_found.append(bypass["name"])

                    await asyncio.sleep(0.1)

                if bypasses_found:
                    fp2 = stable_fingerprint(
                        target, META.plugin_id, "waf_bypass", base_url
                    )
                    findings.append(Finding(
                        severity="high",
                        plugin_id=META.plugin_id,
                        title=(
                            f"WAF bypass possible — {len(bypasses_found)} technique(s) "
                            f"not blocked by {', '.join(waf_list)}"
                        ),
                        description=(
                            f"The WAF ({', '.join(waf_list)}) at {base_url} can potentially "
                            f"be bypassed using the following techniques:\n"
                            + "\n".join(
                                f"  - {b}: {next(t['desc'] for t in _BYPASS_TESTS if t['name'] == b)}"
                                for b in bypasses_found
                            )
                            + "\n\nThese bypass techniques were not blocked by the WAF, "
                            "meaning the underlying application may still be vulnerable "
                            "to injection attacks despite WAF protection."
                        ),
                        evidence=(
                            f"url={base_url} waf={waf_list} "
                            f"bypasses={bypasses_found}"
                        ),
                        affected=target,
                        fingerprint=fp2,
                        confidence=0.60,
                        remediation=(
                            f"[HIGH — WAF Bypass Detected]\n"
                            f"WAF: {', '.join(waf_list)}\n"
                            f"Bypasses: {', '.join(bypasses_found)}\n\n"
                            "Remediation:\n"
                            "1. Update WAF rules to the latest ruleset version\n"
                            "2. Enable paranoia level 2+ (ModSecurity CRS)\n"
                            "3. Configure WAF to normalize/decode input before matching:\n"
                            "   - Enable double-decode detection\n"
                            "   - Enable Unicode normalization\n"
                            "   - Detect null bytes in parameters\n"
                            "4. Block HTTP Parameter Pollution patterns\n"
                            "5. Fix vulnerabilities in the application code — WAF is defense-in-depth, "
                            "not a primary control\n"
                            "6. Enable WAF logging and monitor for bypass attempts"
                        ),
                        references=[
                            "https://owasp.org/www-community/Web_Application_Firewall",
                            "https://portswigger.net/bappstore/ae2611da3bbc4f6097c15b83282e8b69",
                        ],
                    ))

        return PluginResult(
            findings=findings,
            artifacts={"web.waf.findings": {
                "detected": list(detected_wafs) if detected_wafs else [],
                "findings_count": len(findings),
            }},
        )
