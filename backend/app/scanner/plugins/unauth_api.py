"""
Unauthenticated API Access Scanner
Tests common API endpoints for responses that return data without authentication.
Detects broken access control where API endpoints serve user data without tokens.
"""
import asyncio
import json
import re
import ssl
import urllib.parse

from app.scanner.plugins.base import Plugin, PluginMeta, PluginResult, Finding
from app.scanner.context import stable_fingerprint

META = PluginMeta(
    plugin_id="web.unauth_api",
    name="Unauthenticated API Access",
    category="web",
    depends_on=["fingerprint.http"],
    consumes=["fingerprint.http", "net.open_ports", "recon.directories"],
    provides=["web.unauth_api_findings"],
    enabled_by_default=True,
    timeout_seconds=30.0,
)

# API paths that should require authentication
_SENSITIVE_API_PATHS = [
    # User data
    ("/api/users", "User listing"),
    ("/api/v1/users", "User listing (v1)"),
    ("/api/v2/users", "User listing (v2)"),
    ("/api/user", "Current user"),
    ("/api/me", "Current user profile"),
    ("/api/profile", "User profile"),
    ("/api/account", "Account info"),
    ("/api/users/1", "User by ID"),
    ("/api/users/admin", "Admin user"),
    # Admin
    ("/api/admin", "Admin panel"),
    ("/api/admin/users", "Admin user list"),
    ("/api/admin/settings", "Admin settings"),
    ("/api/admin/dashboard", "Admin dashboard"),
    ("/admin/api", "Admin API"),
    # Data
    ("/api/orders", "Orders"),
    ("/api/invoices", "Invoices"),
    ("/api/payments", "Payments"),
    ("/api/transactions", "Transactions"),
    ("/api/customers", "Customers"),
    ("/api/documents", "Documents"),
    ("/api/files", "Files"),
    ("/api/messages", "Messages"),
    ("/api/notifications", "Notifications"),
    # Config
    ("/api/config", "Configuration"),
    ("/api/settings", "Settings"),
    ("/api/env", "Environment"),
    ("/api/debug", "Debug info"),
    ("/api/status", "Status"),
    ("/api/health", "Health"),
    ("/api/info", "Info"),
    ("/api/swagger.json", "Swagger spec"),
    ("/api/openapi.json", "OpenAPI spec"),
    ("/swagger.json", "Swagger spec"),
    ("/openapi.json", "OpenAPI spec"),
    ("/api-docs", "API documentation"),
    ("/docs", "Documentation"),
    # Internal
    ("/api/internal", "Internal API"),
    ("/api/private", "Private API"),
    ("/api/keys", "API keys"),
    ("/api/tokens", "Tokens"),
    ("/api/credentials", "Credentials"),
    ("/api/secrets", "Secrets"),
    # GraphQL (without auth)
    ("/graphql", "GraphQL"),
    # Actuator (Spring Boot)
    ("/actuator", "Spring Actuator"),
    ("/actuator/env", "Environment"),
    ("/actuator/configprops", "Config properties"),
    ("/actuator/mappings", "URL mappings"),
    ("/actuator/beans", "Spring beans"),
]

# Indicators that response contains real data (not an error page)
_DATA_INDICATORS = [
    # JSON structures
    r'"id"\s*:', r'"email"\s*:', r'"username"\s*:', r'"name"\s*:',
    r'"password"\s*:', r'"token"\s*:', r'"secret"\s*:', r'"key"\s*:',
    r'"user"\s*:', r'"admin"\s*:', r'"role"\s*:', r'"data"\s*:',
    r'"items"\s*:\s*\[', r'"results"\s*:\s*\[', r'"count"\s*:',
    # Sensitive data patterns
    r'@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',  # Email addresses
    r'"phone"\s*:', r'"address"\s*:', r'"credit_card"\s*:',
]

# Patterns that indicate "not found" or error (false positive filters)
_ERROR_INDICATORS = [
    "not found", "404", "unauthorized", "forbidden", "not authenticated",
    "login required", "please log in", "access denied", "invalid token",
    "no token", "authentication required",
]


async def _fetch(host: str, port: int, path: str, use_tls: bool,
                 timeout: float = 5.0) -> tuple[int, str, dict]:
    """Send GET request without auth, return (status, body, headers)."""
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
            f"Accept: application/json, text/html\r\n"
            f"Connection: close\r\n\r\n"
        )
        writer.write(request.encode())
        await writer.drain()

        response = await asyncio.wait_for(reader.read(32768), timeout=timeout)
        writer.close()

        text = response.decode("utf-8", errors="ignore")
        parts = text.split("\r\n\r\n", 1)
        header_block = parts[0] if parts else ""
        body = parts[1] if len(parts) > 1 else ""

        status_match = re.match(r"HTTP/\d\.\d\s+(\d+)", header_block)
        status = int(status_match.group(1)) if status_match else 0

        headers = {}
        for line in header_block.split("\r\n")[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()

        return status, body, headers
    except Exception:
        return 0, "", {}


def _has_data(body: str) -> tuple[bool, list[str]]:
    """Check if response contains real data (not just an error page)."""
    body_lower = body.lower()

    # Reject if it looks like an error page
    for err in _ERROR_INDICATORS:
        if err in body_lower:
            return False, []

    # Check for data indicators
    matched = []
    for pattern in _DATA_INDICATORS:
        if re.search(pattern, body, re.I):
            matched.append(pattern)

    return len(matched) >= 2, matched


def _classify_severity(path: str, body: str) -> str:
    """Classify severity based on what data is exposed."""
    critical_keywords = ["password", "secret", "token", "key", "credential", "credit_card"]
    high_keywords = ["email", "user", "admin", "account", "order", "payment", "invoice"]

    path_lower = path.lower()
    body_lower = body.lower()[:2000]

    for kw in critical_keywords:
        if kw in body_lower or kw in path_lower:
            return "critical"

    for kw in high_keywords:
        if kw in body_lower or kw in path_lower:
            return "high"

    return "medium"


class Check(Plugin):
    async def run(self, target: str, ctx) -> PluginResult:
        ports = ctx.get("net.open_ports", []) or []
        http_data = (ctx.get("fingerprint.http", {}) or {}).get("http", [])
        target_raw = ctx.get("target_raw", target)
        directories = ctx.get("recon.directories", []) or []
        findings = []
        api_results = []

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
            return PluginResult(artifacts={"web.unauth_api_findings": []})

        for base in base_urls[:2]:
            parsed = urllib.parse.urlparse(base)
            host = parsed.hostname or target
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            use_tls = parsed.scheme == "https"

            # Combine with discovered directories
            test_paths = list(_SENSITIVE_API_PATHS)
            for d in directories[:15]:
                if any(kw in d.lower() for kw in ["api", "admin", "user", "graphql", "swagger", "docs"]):
                    test_paths.append((d, f"Discovered: {d}"))

            # Test each path WITHOUT authentication
            for path_info in test_paths:
                if isinstance(path_info, tuple):
                    path, desc = path_info
                else:
                    path, desc = path_info, path_info

                status, body, headers = await _fetch(host, port, path, use_tls)

                # Only interested in 200 responses with real data
                if status != 200 or len(body) < 50:
                    continue

                has_data, matched_patterns = _has_data(body)
                if not has_data:
                    continue

                # Check content type
                content_type = headers.get("content-type", "")
                is_json = "json" in content_type or body.strip().startswith(("{", "["))

                # Count items if it's a JSON array
                item_count = 0
                if is_json:
                    try:
                        data = json.loads(body)
                        if isinstance(data, list):
                            item_count = len(data)
                        elif isinstance(data, dict):
                            for key in ["items", "results", "data", "users", "records"]:
                                if key in data and isinstance(data[key], list):
                                    item_count = len(data[key])
                                    break
                    except Exception:
                        pass

                severity = _classify_severity(path, body)
                fp = stable_fingerprint(target, META.plugin_id, path)

                findings.append(Finding(
                    severity=severity,
                    plugin_id=META.plugin_id,
                    title=f"Unauthenticated API access: {desc}",
                    description=(
                        f"The API endpoint {path} returns data without any authentication. "
                        f"Response contains {len(matched_patterns)} data indicator(s). "
                        + (f"JSON response with {item_count} item(s). " if item_count > 0 else "")
                        + "Any unauthenticated user can access this data."
                    ),
                    evidence=(
                        f"url={base}{path} status={status} body_len={len(body)} "
                        f"content_type={content_type} is_json={is_json} "
                        f"items={item_count} indicators={matched_patterns[:5]} "
                        f"preview={body[:200]}"
                    ),
                    affected=target,
                    fingerprint=fp,
                    confidence=0.85,
                    remediation=(
                        f"[{severity.upper()}] Unauthenticated access to {path}\n\n"
                        f"[FIX]\n"
                        f"1. Require authentication for all API endpoints that return data\n"
                        f"2. Add middleware to check JWT/session before serving responses\n"
                        f"3. Return 401 Unauthorized for unauthenticated requests\n"
                        f"4. Implement proper RBAC for different user roles\n\n"
                        f"[EXPRESS.JS]\n"
                        f"  app.use('/api', authMiddleware);\n\n"
                        f"[DJANGO]\n"
                        f"  @permission_classes([IsAuthenticated])\n\n"
                        f"[ALSO]\n"
                        f"- Remove or protect Swagger/OpenAPI documentation endpoints\n"
                        f"- Disable Spring Actuator endpoints in production\n"
                        f"- Never expose admin APIs without authentication"
                    ),
                    references=[
                        "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
                    ],
                ))
                api_results.append({"path": path, "severity": severity, "items": item_count})

        return PluginResult(findings=findings, artifacts={"web.unauth_api_findings": api_results})
