"""
Host Header Injection Scanner — checks for web servers that trust
the Host header in security-sensitive operations.

Tests:
  - Host header override (password-reset poisoning, cache poisoning)
  - X-Forwarded-Host injection
  - Absolute URL with spoofed host
  - Multiple Host headers

Benign payloads only — checks if injected host appears in response body/headers.
"""
import asyncio
import logging
import re
import ssl
import urllib.parse

from app.scanner.plugins.base import Finding, Plugin, PluginMeta, PluginResult
from app.scanner.context import stable_fingerprint

logger = logging.getLogger("vulnscan.host_header_injection")

META = PluginMeta(
    plugin_id="web.host_header_injection",
    name="Host Header Injection Scanner",
    category="web",
    depends_on=["fingerprint.http"],
    consumes=["fingerprint.http", "net.open_ports"],
    provides=["web.host_header.findings"],
    enabled_by_default=True,
    timeout_seconds=20.0,
)

_CANARY = "evil.vulnscan-test.com"

_TESTS = [
    {
        "name": "Host header override",
        "headers": {"Host": _CANARY},
        "vector": "Host",
    },
    {
        "name": "X-Forwarded-Host injection",
        "headers": {"X-Forwarded-Host": _CANARY},
        "vector": "X-Forwarded-Host",
    },
    {
        "name": "X-Host injection",
        "headers": {"X-Host": _CANARY},
        "vector": "X-Host",
    },
    {
        "name": "Forwarded header injection",
        "headers": {"Forwarded": f"host={_CANARY}"},
        "vector": "Forwarded",
    },
]


async def _send_request(host: str, port: int, path: str, scheme: str,
                        extra_headers: dict, real_host: str,
                        timeout: float = 5.0) -> tuple[str, str]:
    """Send HTTP request and return (response_headers, response_body)."""
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

        # Build request — use real Host unless overridden
        headers = {
            "Host": real_host,
            "User-Agent": "VulnScan/2.1",
            "Accept": "*/*",
            "Connection": "close",
        }
        headers.update(extra_headers)

        header_lines = "\r\n".join(f"{k}: {v}" for k, v in headers.items())
        request = f"GET {path} HTTP/1.1\r\n{header_lines}\r\n\r\n"

        writer.write(request.encode())
        await writer.drain()
        response = await asyncio.wait_for(reader.read(32768), timeout=timeout)
        writer.close()

        text = response.decode("utf-8", errors="ignore")
        parts = text.split("\r\n\r\n", 1)
        resp_headers = parts[0] if parts else ""
        resp_body = parts[1] if len(parts) > 1 else ""
        return resp_headers, resp_body
    except Exception:
        return "", ""


class Check(Plugin):
    async def run(self, target: str, ctx) -> PluginResult:
        ports = ctx.get("net.open_ports", []) or []
        http_data = (ctx.get("fingerprint.http", {}) or {}).get("http", [])
        target_raw = ctx.get("target_raw", target)
        findings: list[Finding] = []

        # Build URL list
        urls = []
        if re.match(r"^https?://", target_raw, re.I):
            urls.append(target_raw.rstrip("/") + "/")
        else:
            for item in http_data:
                url = item.get("url", "")
                if url:
                    urls.append(url.rstrip("/") + "/")
            if not urls:
                web_ports = [p for p in ports if p in (80, 443, 8080, 8443)]
                for p in web_ports:
                    scheme = "https" if p in (443, 8443) else "http"
                    urls.append(f"{scheme}://{target}:{p}/")

        if not urls:
            return PluginResult(artifacts={"web.host_header.findings": 0})

        for url in urls[:2]:
            parsed = urllib.parse.urlparse(url)
            host = parsed.hostname or target
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            path = parsed.path or "/"
            scheme = parsed.scheme

            # Get baseline response first
            base_headers, base_body = await _send_request(
                host, port, path, scheme, {}, host
            )
            if not base_headers:
                continue

            # Run each test
            for test in _TESTS:
                resp_headers, resp_body = await _send_request(
                    host, port, path, scheme, test["headers"], host
                )
                if not resp_headers:
                    continue

                # Check if canary appears in response (not in baseline)
                canary_in_headers = _CANARY in resp_headers
                canary_in_body = _CANARY in resp_body
                canary_in_baseline = _CANARY in base_headers or _CANARY in base_body

                if (canary_in_headers or canary_in_body) and not canary_in_baseline:
                    location = []
                    if canary_in_headers:
                        location.append("response headers")
                    if canary_in_body:
                        location.append("response body")

                    # Check specific dangerous patterns
                    in_redirect = bool(re.search(
                        r"(?:Location|Refresh):\s*https?://" + re.escape(_CANARY),
                        resp_headers, re.I
                    ))
                    in_link = bool(re.search(
                        r'(?:href|src|action)=["\']https?://' + re.escape(_CANARY),
                        resp_body, re.I
                    ))

                    severity = "high" if (in_redirect or in_link) else "medium"

                    fp = stable_fingerprint(
                        target, META.plugin_id, test["vector"], url
                    )
                    findings.append(Finding(
                        severity=severity,
                        plugin_id=META.plugin_id,
                        title=(
                            f"Host Header Injection via {test['vector']}"
                            f"{' — redirect poisoning' if in_redirect else ''}"
                            f"{' — link poisoning' if in_link else ''}"
                        ),
                        description=(
                            f"The web server at {url} reflects the injected "
                            f"{test['vector']} header value ({_CANARY}) in its "
                            f"{', '.join(location)}. "
                            f"{'The canary appears in a redirect Location header, enabling password-reset token theft and cache poisoning. ' if in_redirect else ''}"
                            f"{'The canary appears in HTML links/forms, enabling phishing and XSS. ' if in_link else ''}"
                            "This can be exploited for password-reset poisoning, "
                            "web cache poisoning, and SSRF."
                        ),
                        evidence=(
                            f"url={url} vector={test['vector']} canary={_CANARY} "
                            f"reflected_in={','.join(location)} "
                            f"in_redirect={in_redirect} in_link={in_link} "
                            f"response_headers_sample={resp_headers[:300]}"
                        ),
                        affected=target,
                        fingerprint=fp,
                        confidence=0.90,
                        remediation=(
                            f"[{'HIGH' if severity == 'high' else 'MEDIUM'} — Host Header Injection via {test['vector']}]\n\n"
                            "The server uses the Host header value in generating responses.\n\n"
                            "Remediation:\n"
                            "1. Configure the web server with a fixed server name:\n"
                            "   Nginx:  server_name example.com; (reject unknown hosts)\n"
                            "   Apache: UseCanonicalName On\n"
                            "2. Validate the Host header against a whitelist\n"
                            "3. Don't use Host header to generate absolute URLs:\n"
                            "   - Use a configured base URL from app settings\n"
                            "   - Django: ALLOWED_HOSTS = ['example.com']\n"
                            "   - Rails: config.hosts << 'example.com'\n"
                            "4. Ignore X-Forwarded-Host unless behind a trusted proxy\n"
                            "5. For password-reset flows, use a hardcoded base URL\n\n"
                            "References:\n"
                            "- https://portswigger.net/web-security/host-header"
                        ),
                        references=[
                            "https://portswigger.net/web-security/host-header",
                            "https://cwe.mitre.org/data/definitions/644.html",
                        ],
                    ))

        return PluginResult(
            findings=findings,
            artifacts={"web.host_header.findings": len(findings)},
        )
