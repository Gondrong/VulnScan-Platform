"""
CRLF Injection Scanner — checks for HTTP response splitting vulnerabilities.

Tests if user input containing \\r\\n (CRLF) characters is reflected in
HTTP response headers, enabling:
  - HTTP Response Splitting
  - Header Injection (Set-Cookie, Location)
  - XSS via injected headers
  - Cache Poisoning

Benign payloads only — injects a harmless custom header as proof of concept.
"""
import asyncio
import logging
import re
import ssl
import urllib.parse

from app.scanner.plugins.base import Finding, Plugin, PluginMeta, PluginResult
from app.scanner.context import stable_fingerprint

logger = logging.getLogger("vulnscan.crlf_injection")

META = PluginMeta(
    plugin_id="web.crlf_injection",
    name="CRLF Injection Scanner",
    category="web",
    depends_on=["fingerprint.http"],
    consumes=["fingerprint.http", "net.open_ports"],
    provides=["web.crlf.findings"],
    enabled_by_default=True,
    timeout_seconds=20.0,
)

_CANARY_HEADER = "X-VulnScan-CRLF"
_CANARY_VALUE = "injected"

# CRLF payloads — each tries to inject our canary header into the response
_PAYLOADS = [
    {
        "name": "Basic CRLF",
        "suffix": f"%0d%0a{_CANARY_HEADER}:%20{_CANARY_VALUE}",
        "encoded": True,
    },
    {
        "name": "Double-encoded CRLF",
        "suffix": f"%250d%250a{_CANARY_HEADER}:%20{_CANARY_VALUE}",
        "encoded": True,
    },
    {
        "name": "Unicode CRLF",
        "suffix": f"%E5%98%8A%E5%98%8D{_CANARY_HEADER}:%20{_CANARY_VALUE}",
        "encoded": True,
    },
    {
        "name": "Bare \\r\\n CRLF",
        "suffix": f"\r\n{_CANARY_HEADER}: {_CANARY_VALUE}",
        "encoded": False,
    },
    {
        "name": "Header injection via \\n",
        "suffix": f"%0a{_CANARY_HEADER}:%20{_CANARY_VALUE}",
        "encoded": True,
    },
]

# Paths commonly vulnerable to CRLF (redirect endpoints, lang params)
_TEST_PATHS = [
    "/",
    "/?url=",
    "/?redirect=",
    "/?next=",
    "/?return=",
    "/?dest=",
    "/?lang=en",
    "/login?next=",
    "/redirect?url=",
]


async def _send_raw(host: str, port: int, scheme: str,
                    request: str, timeout: float = 5.0) -> str:
    """Send raw HTTP request and return full response."""
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

        writer.write(request.encode("latin-1"))
        await writer.drain()
        data = await asyncio.wait_for(reader.read(16384), timeout=timeout)
        writer.close()
        return data.decode("utf-8", errors="ignore")
    except Exception:
        return ""


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
            return PluginResult(artifacts={"web.crlf.findings": 0})

        found_vulns = set()  # Track unique (url_base, payload_name) combos

        for base_url in urls[:2]:
            parsed = urllib.parse.urlparse(base_url)
            host = parsed.hostname or target
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            scheme = parsed.scheme

            for test_path in _TEST_PATHS:
                for payload in _PAYLOADS:
                    # Build the full path with CRLF payload
                    if payload["encoded"]:
                        full_path = test_path + payload["suffix"]
                    else:
                        full_path = test_path + payload["suffix"]

                    request = (
                        f"GET {full_path} HTTP/1.1\r\n"
                        f"Host: {host}\r\n"
                        f"User-Agent: VulnScan/2.1\r\n"
                        f"Connection: close\r\n\r\n"
                    )

                    resp = await _send_raw(host, port, scheme, request)
                    if not resp:
                        continue

                    # Split into headers and body
                    parts = resp.split("\r\n\r\n", 1)
                    resp_headers = parts[0] if parts else ""

                    # Check if our canary header appears in the response headers
                    canary_pattern = re.compile(
                        re.escape(_CANARY_HEADER) + r":\s*" + re.escape(_CANARY_VALUE),
                        re.I,
                    )
                    if canary_pattern.search(resp_headers):
                        vuln_key = (base_url, payload["name"])
                        if vuln_key in found_vulns:
                            continue
                        found_vulns.add(vuln_key)

                        fp = stable_fingerprint(
                            target, META.plugin_id, payload["name"],
                            test_path, base_url
                        )
                        findings.append(Finding(
                            severity="high",
                            plugin_id=META.plugin_id,
                            title=(
                                f"CRLF Injection — {payload['name']} on "
                                f"{test_path}"
                            ),
                            description=(
                                f"The web server at {base_url}{test_path} is vulnerable "
                                f"to CRLF injection via {payload['name']}. "
                                f"The injected header '{_CANARY_HEADER}: {_CANARY_VALUE}' "
                                f"was reflected in the HTTP response headers. "
                                f"This enables HTTP response splitting, header injection "
                                f"(e.g., Set-Cookie for session fixation), XSS via "
                                f"injected Content-Type, and web cache poisoning."
                            ),
                            evidence=(
                                f"url={base_url}{test_path} payload={payload['name']} "
                                f"injected_header={_CANARY_HEADER}:{_CANARY_VALUE} "
                                f"response_headers={resp_headers[:400]}"
                            ),
                            affected=target,
                            fingerprint=fp,
                            confidence=0.95,
                            remediation=(
                                "[HIGH — CRLF Injection / HTTP Response Splitting]\n\n"
                                "User input containing CR (\\r) or LF (\\n) characters is "
                                "being included in HTTP response headers.\n\n"
                                "Remediation:\n"
                                "1. Strip or reject \\r and \\n from all user input\n"
                                "   used in HTTP headers (redirects, cookies, etc.)\n"
                                "2. Use framework-provided redirect functions:\n"
                                "   - Django: HttpResponseRedirect() (auto-sanitizes)\n"
                                "   - Express: res.redirect() (auto-sanitizes)\n"
                                "   - Spring: RedirectView (auto-sanitizes)\n"
                                "3. URL-encode all user input before using in headers\n"
                                "4. Use an allowlist for redirect targets\n"
                                "5. Configure WAF rules to block CRLF in URLs\n\n"
                                "Attack vectors:\n"
                                "- Set-Cookie injection → session fixation\n"
                                "- Location header → open redirect\n"
                                "- Content-Type: text/html → XSS\n"
                                "- HTTP/1.1 response splitting → cache poisoning"
                            ),
                            references=[
                                "https://owasp.org/www-community/vulnerabilities/CRLF_Injection",
                                "https://cwe.mitre.org/data/definitions/113.html",
                            ],
                        ))

                # Rate-limit: don't hammer the target
                await asyncio.sleep(0.05)

        return PluginResult(
            findings=findings,
            artifacts={"web.crlf.findings": len(findings)},
        )
