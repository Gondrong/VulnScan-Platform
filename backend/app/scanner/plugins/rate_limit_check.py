"""
Rate Limiting Check Plugin
Tests if login and API endpoints enforce rate limiting by sending
rapid requests and checking for 429/block responses.
"""
import asyncio
import re
import ssl
import time
import urllib.parse

from app.scanner.plugins.base import Plugin, PluginMeta, PluginResult, Finding
from app.scanner.context import stable_fingerprint

META = PluginMeta(
    plugin_id="web.rate_limit",
    name="Rate Limiting Check",
    category="web",
    depends_on=["fingerprint.http"],
    consumes=["fingerprint.http", "net.open_ports"],
    provides=["web.rate_limit"],
    enabled_by_default=True,
    timeout_seconds=30.0,
)

# Endpoints to test for rate limiting
_TEST_ENDPOINTS = [
    ("/login", "POST", '{"username":"test","password":"wrong"}'),
    ("/api/login", "POST", '{"email":"test@test.com","password":"wrong"}'),
    ("/auth/login", "POST", '{"email":"test@test.com","password":"wrong"}'),
    ("/api/auth/login", "POST", '{"email":"test@test.com","password":"wrong"}'),
    ("/api/v1/auth/login", "POST", '{"email":"test@test.com","password":"wrong"}'),
    ("/signin", "POST", '{"username":"test","password":"wrong"}'),
    ("/api/signin", "POST", '{"username":"test","password":"wrong"}'),
]

_RAPID_COUNT = 30  # Number of rapid requests to send
_RAPID_WINDOW = 5  # Seconds to send them in


async def _http_request(host: str, port: int, method: str, path: str,
                        body: str = "", use_tls: bool = False,
                        timeout: float = 5.0) -> tuple[int, dict, str]:
    """Send HTTP request, return (status, headers, body)."""
    try:
        if use_tls:
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

        headers = {
            "Host": host,
            "User-Agent": "VulnScan/2.1",
            "Accept": "*/*",
            "Content-Type": "application/json",
            "Connection": "close",
        }
        if body:
            headers["Content-Length"] = str(len(body))

        request = f"{method} {path} HTTP/1.1\r\n"
        request += "".join(f"{k}: {v}\r\n" for k, v in headers.items())
        request += f"\r\n{body}"

        writer.write(request.encode())
        await writer.drain()

        response = await asyncio.wait_for(reader.read(8192), timeout=timeout)
        writer.close()

        text = response.decode("utf-8", errors="ignore")
        parts = text.split("\r\n\r\n", 1)
        header_block = parts[0] if parts else ""
        resp_body = parts[1] if len(parts) > 1 else ""

        status_match = re.match(r"HTTP/\d\.\d\s+(\d+)", header_block)
        status = int(status_match.group(1)) if status_match else 0

        resp_headers = {}
        for line in header_block.split("\r\n")[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                resp_headers[k.strip().lower()] = v.strip()

        return status, resp_headers, resp_body
    except Exception:
        return 0, {}, ""


class Check(Plugin):
    async def run(self, target: str, ctx) -> PluginResult:
        ports = ctx.get("net.open_ports", []) or []
        http_data = (ctx.get("fingerprint.http", {}) or {}).get("http", [])
        target_raw = ctx.get("target_raw", target)
        findings = []
        results = {}

        # Determine base URLs
        base_urls = []
        if re.match(r"^https?://", target_raw, re.I):
            base_urls.append(target_raw.rstrip("/"))
        else:
            for item in http_data:
                url = item.get("url", "")
                if url:
                    base_urls.append(url.rstrip("/"))
            if not base_urls:
                web_ports = [p for p in ports if p in (80, 443, 8080, 8443, 3000, 5000, 8000, 8888)]
                for p in web_ports[:2]:
                    scheme = "https" if p in (443, 8443) else "http"
                    base_urls.append(f"{scheme}://{target}:{p}")

        if not base_urls:
            return PluginResult(artifacts={"web.rate_limit": {}})

        for base in base_urls[:2]:
            parsed = urllib.parse.urlparse(base)
            host = parsed.hostname or target
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            use_tls = parsed.scheme == "https"

            for path, method, body in _TEST_ENDPOINTS:
                # First check if endpoint exists
                status, headers, resp_body = await _http_request(
                    host, port, method, path, body, use_tls
                )

                # Skip if endpoint doesn't exist (404) or method not allowed (405)
                if status in (0, 404, 405):
                    continue

                # Endpoint exists — now rapid-fire test
                statuses = []
                start = time.time()

                tasks = []
                for i in range(_RAPID_COUNT):
                    tasks.append(_http_request(host, port, method, path, body, use_tls, timeout=3.0))

                responses = await asyncio.gather(*tasks, return_exceptions=True)
                elapsed = time.time() - start

                for r in responses:
                    if isinstance(r, Exception):
                        statuses.append(0)
                    else:
                        statuses.append(r[0])

                # Analyze results
                status_429 = statuses.count(429)
                status_403 = statuses.count(403)
                status_200 = statuses.count(200)
                status_401 = statuses.count(401)
                blocked = status_429 + status_403
                allowed = status_200 + status_401

                url = f"{base}{path}"

                if blocked == 0 and allowed > 20:
                    # No rate limiting detected
                    fp = stable_fingerprint(target, META.plugin_id, "no_limit", path)
                    findings.append(Finding(
                        severity="high",
                        plugin_id=META.plugin_id,
                        title=f"No rate limiting on {method} {path}",
                        description=(
                            f"Sent {_RAPID_COUNT} requests to {url} in {elapsed:.1f}s. "
                            f"All {allowed} requests were processed without throttling or blocking. "
                            f"An attacker can brute-force credentials or abuse this endpoint."
                        ),
                        evidence=(
                            f"url={url} method={method} requests={_RAPID_COUNT} "
                            f"elapsed={elapsed:.1f}s 200s={status_200} 401s={status_401} "
                            f"429s={status_429} 403s={status_403}"
                        ),
                        affected=target,
                        fingerprint=fp,
                        confidence=0.90,
                        remediation=(
                            f"[AFFECTED] No rate limiting on {method} {path}\n\n"
                            f"[FIX] Implement rate limiting:\n"
                            f"  Nginx: limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;\n"
                            f"  Express: app.use('/login', rateLimit({{ windowMs: 60000, max: 5 }}))\n"
                            f"  Django: django-ratelimit decorator\n\n"
                            f"[ALSO]\n"
                            f"  - Implement account lockout after 5 failed attempts\n"
                            f"  - Add CAPTCHA after 3 failed attempts\n"
                            f"  - Use exponential backoff for repeated failures"
                        ),
                        references=["https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html"],
                    ))
                    results[path] = "no_limit"
                    break  # One unprotected endpoint is enough

                elif blocked > 0:
                    fp = stable_fingerprint(target, META.plugin_id, "has_limit", path)
                    findings.append(Finding(
                        severity="info",
                        plugin_id=META.plugin_id,
                        title=f"Rate limiting active on {method} {path}",
                        description=(
                            f"Rate limiting is enforced on {url}. "
                            f"{blocked}/{_RAPID_COUNT} requests were blocked (429/403)."
                        ),
                        evidence=f"url={url} blocked={blocked}/{_RAPID_COUNT} 429s={status_429} 403s={status_403}",
                        affected=target,
                        fingerprint=fp,
                        confidence=1.0,
                        remediation="Rate limiting is configured correctly.",
                    ))
                    results[path] = "rate_limited"
                    break

        return PluginResult(findings=findings, artifacts={"web.rate_limit": results})
