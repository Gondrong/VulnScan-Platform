"""
Open Redirect Scanner
Tests URL parameters for unvalidated redirects to external domains.
"""
import asyncio
import re
import ssl
import urllib.parse

from app.scanner.plugins.base import Plugin, PluginMeta, PluginResult, Finding
from app.scanner.context import stable_fingerprint

META = PluginMeta(
    plugin_id="web.open_redirect",
    name="Open Redirect Scanner",
    category="web",
    depends_on=["fingerprint.http"],
    consumes=["fingerprint.http", "net.open_ports", "recon.directories"],
    provides=["web.open_redirects"],
    enabled_by_default=True,
    timeout_seconds=30.0,
)

# Common redirect parameter names
_REDIRECT_PARAMS = [
    "redirect", "redirect_url", "redirect_uri", "return", "return_url",
    "returnTo", "return_to", "next", "url", "goto", "target", "dest",
    "destination", "rurl", "continue", "forward", "callback", "cb",
    "out", "view", "login_url", "logout", "ref", "referrer",
]

# Payloads — different bypass techniques
_EVIL_DOMAIN = "evil-redirect-test.com"
_PAYLOADS = [
    f"https://{_EVIL_DOMAIN}",
    f"//{_EVIL_DOMAIN}",
    f"https://{_EVIL_DOMAIN}%00.legitimate.com",
    f"https://{_EVIL_DOMAIN}?.legitimate.com",
    f"https://{_EVIL_DOMAIN}#.legitimate.com",
    f"https://{_EVIL_DOMAIN}/.legitimate.com",
    f"/\\{_EVIL_DOMAIN}",
    f"https:{_EVIL_DOMAIN}",
    f"\t//{_EVIL_DOMAIN}",
]

# Paths that commonly have redirect parameters
_REDIRECT_PATHS = [
    "/login", "/signin", "/auth", "/oauth", "/callback",
    "/logout", "/redirect", "/sso", "/saml",
]


async def _fetch(host: str, port: int, path: str, use_tls: bool,
                 timeout: float = 5.0) -> tuple[int, dict]:
    """Send GET request, return (status, headers)."""
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

        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: VulnScan/2.1\r\n"
            f"Accept: */*\r\n"
            f"Connection: close\r\n\r\n"
        )
        writer.write(request.encode())
        await writer.drain()

        response = await asyncio.wait_for(reader.read(4096), timeout=timeout)
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
        directories = ctx.get("recon.directories", []) or []
        findings = []
        redirects_found = []

        # Determine host/port
        base_urls = []
        if re.match(r"^https?://", target_raw, re.I):
            base_urls.append(target_raw.rstrip("/"))
        else:
            for item in http_data:
                url = item.get("url", "")
                if url:
                    base_urls.append(url.rstrip("/"))
            if not base_urls:
                web_ports = [p for p in ports if p in (80, 443, 8080, 8443)]
                for p in web_ports[:2]:
                    scheme = "https" if p in (443, 8443) else "http"
                    base_urls.append(f"{scheme}://{target}:{p}")

        if not base_urls:
            return PluginResult(artifacts={"web.open_redirects": []})

        for base in base_urls[:2]:
            parsed = urllib.parse.urlparse(base)
            host = parsed.hostname or target
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            use_tls = parsed.scheme == "https"

            # Combine standard redirect paths with discovered directories
            test_paths = list(_REDIRECT_PATHS)
            for d in directories[:10]:
                if any(kw in d.lower() for kw in ["login", "auth", "redirect", "callback", "sso"]):
                    test_paths.append(d)

            for base_path in test_paths:
                for param in _REDIRECT_PARAMS[:10]:  # Top 10 params
                    for payload in _PAYLOADS[:4]:  # Top 4 payloads
                        test_path = f"{base_path}?{param}={urllib.parse.quote(payload)}"
                        status, headers = await _fetch(host, port, test_path, use_tls)

                        if status in (301, 302, 303, 307, 308):
                            location = headers.get("location", "")
                            if _EVIL_DOMAIN in location.lower():
                                url = f"{base}{test_path}"
                                fp = stable_fingerprint(target, META.plugin_id, base_path, param)
                                findings.append(Finding(
                                    severity="medium",
                                    plugin_id=META.plugin_id,
                                    title=f"Open redirect: {base_path}?{param}=",
                                    description=(
                                        f"The endpoint {base_path} redirects to an attacker-controlled domain "
                                        f"via the '{param}' parameter. An attacker can craft a URL that appears "
                                        f"to be from your domain but redirects victims to a phishing page."
                                    ),
                                    evidence=(
                                        f"url={url} status={status} "
                                        f"location={location} param={param} "
                                        f"payload={payload}"
                                    ),
                                    affected=target,
                                    fingerprint=fp,
                                    confidence=0.95,
                                    remediation=(
                                        f"[AFFECTED] Open redirect at {base_path}?{param}=\n\n"
                                        f"[FIX]\n"
                                        f"1. Validate redirect URLs against a whitelist of allowed domains\n"
                                        f"2. Only allow relative redirects (starting with /)\n"
                                        f"3. Use a mapping table instead of URL parameters\n\n"
                                        f"[CODE EXAMPLE]\n"
                                        f"  allowed = ['https://yoursite.com', 'https://app.yoursite.com']\n"
                                        f"  if redirect_url not in allowed:\n"
                                        f"      redirect_url = '/dashboard'\n\n"
                                        f"[IMPACT] Phishing, OAuth token theft, credential harvesting"
                                    ),
                                    references=[
                                        "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
                                    ],
                                ))
                                redirects_found.append({"path": base_path, "param": param, "payload": payload})
                                break  # One payload per param is enough
                    if any(r["path"] == base_path for r in redirects_found):
                        break  # Move to next path

        return PluginResult(findings=findings, artifacts={"web.open_redirects": redirects_found})
