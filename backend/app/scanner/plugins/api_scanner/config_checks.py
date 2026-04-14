"""
API Configuration Checks — Passive security analysis
Detects: missing auth, CORS misconfiguration, HTTP method issues,
verbose errors, rate limiting, exposed documentation, API versioning.
"""
import asyncio
import json
import logging
import re
import time

from app.scanner.plugins.base import Finding
from app.scanner.context import stable_fingerprint

logger = logging.getLogger("vulnscan.api_scanner.config")

# OWASP API Security Top 10 references
_OWASP_API = {
    "API1": "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
    "API2": "https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/",
    "API3": "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/",
    "API4": "https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/",
    "API5": "https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/",
    "API8": "https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/",
    "API9": "https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/",
}

# Sensitive documentation paths
_DOC_PATHS = [
    "/swagger-ui", "/swagger-ui/", "/swagger-ui/index.html",
    "/redoc", "/api-docs", "/docs", "/docs/",
    "/graphiql", "/graphql/playground", "/altair",
    "/actuator", "/actuator/env", "/actuator/configprops",
    "/actuator/mappings", "/actuator/beans", "/actuator/health",
    "/metrics", "/prometheus", "/debug", "/debug/vars",
    "/_profiler", "/elmah.axd", "/trace",
]

# Stack trace / debug error patterns
_ERROR_PATTERNS = [
    r"Traceback \(most recent call last\)",
    r"at .+\.java:\d+",
    r"Exception in thread",
    r"Fatal error:",
    r"Stack trace:",
    r"Microsoft\.AspNetCore",
    r"System\.NullReferenceException",
    r"node_modules/",
    r"TypeError:",
    r"SyntaxError:",
    r"ReferenceError:",
    r"SQLSTATE\[",
    r"pg_query\(\)",
    r"mysql_",
    r"ORA-\d{5}",
    r"<title>Error</title>",
    r"DEBUG = True",
    r"\"debug\":\s*true",
    r"X-Debug-Token",
]


async def check(client, endpoints, ctx) -> list[Finding]:
    """Run all passive configuration checks against API endpoints."""
    findings = []
    target = ctx.get("target_raw", "unknown")

    # 1. Missing authentication
    await _check_missing_auth(client, endpoints, target, findings)

    # 2. CORS misconfiguration
    await _check_cors(client, endpoints, target, findings)

    # 3. HTTP method restrictions
    await _check_http_methods(client, endpoints, target, findings)

    # 4. Verbose error messages
    await _check_verbose_errors(client, endpoints, target, findings)

    # 5. Rate limiting
    await _check_rate_limiting(client, endpoints, target, findings)

    # 6. Exposed documentation
    await _check_exposed_docs(client, target, findings)

    return findings


async def _check_missing_auth(client, endpoints, target, findings):
    """Check if endpoints return data without authentication."""
    from .http_client import ApiHttpClient

    # Create a second client WITHOUT auth
    no_auth_client = ApiHttpClient(
        base_url=client.base_url,
        auth_config={},  # No auth
        max_concurrent=3,
        timeout=client.timeout,
    )

    try:
        tested = 0
        for ep in endpoints[:20]:  # Test up to 20 endpoints
            if ep.method not in ("GET", "POST"):
                continue

            # Request WITH auth
            auth_resp = await client.baseline_request(ep)
            if auth_resp.status not in (200, 201):
                continue  # Skip if even auth'd request fails

            # Request WITHOUT auth
            no_auth_resp = await no_auth_client.baseline_request(ep)

            if no_auth_resp.status in (200, 201) and no_auth_resp.body_length > 50:
                # Both return 200 — check if responses are similar (meaning no auth required)
                if abs(no_auth_resp.body_length - auth_resp.body_length) < auth_resp.body_length * 0.3:
                    fp = stable_fingerprint(target, "api.scanner.config", "no_auth", ep.path, ep.method)
                    findings.append(Finding(
                        severity="high",
                        plugin_id="api.scanner.config",
                        title=f"No authentication required: {ep.method} {ep.path}",
                        description=(
                            f"The endpoint {ep.method} {ep.path} returns data without authentication. "
                            f"Unauthenticated response: {no_auth_resp.status} ({no_auth_resp.body_length} bytes). "
                            f"Authenticated response: {auth_resp.status} ({auth_resp.body_length} bytes)."
                        ),
                        evidence=(
                            f"path={ep.path} method={ep.method} "
                            f"no_auth_status={no_auth_resp.status} no_auth_len={no_auth_resp.body_length} "
                            f"auth_status={auth_resp.status} auth_len={auth_resp.body_length}"
                        ),
                        affected=target,
                        fingerprint=fp,
                        confidence=0.85,
                        cvss=7.5,
                        remediation=(
                            f"[HIGH — OWASP API2:2023 Broken Authentication]\n\n"
                            f"[AFFECTED] {ep.method} {ep.path}\n\n"
                            f"[FIX]\n"
                            f"1. Require authentication for all non-public endpoints\n"
                            f"2. Add auth middleware: app.use('/api', authRequired)\n"
                            f"3. Return 401 Unauthorized for unauthenticated requests\n"
                            f"4. Use OAuth 2.0 or JWT for API authentication"
                        ),
                        references=[_OWASP_API["API2"]],
                    ))
                    tested += 1
                    if tested >= 5:
                        break  # Don't flood with findings

    finally:
        await no_auth_client.close()


async def _check_cors(client, endpoints, target, findings):
    """Check CORS configuration."""
    evil_origin = "https://evil-attacker.com"

    for ep in endpoints[:10]:
        resp = await client.request(
            ep.method, ep.path,
            headers={"Origin": evil_origin},
        )

        if resp.status == 0:
            continue

        acao = resp.headers.get("access-control-allow-origin", "")
        acac = resp.headers.get("access-control-allow-credentials", "")

        if acao == evil_origin:
            sev = "critical" if acac.lower() == "true" else "high"
            fp = stable_fingerprint(target, "api.scanner.config", "cors_reflect", ep.path)
            findings.append(Finding(
                severity=sev,
                plugin_id="api.scanner.config",
                title=f"CORS reflects arbitrary Origin: {ep.method} {ep.path}",
                description=(
                    f"The API reflects the attacker's Origin header in Access-Control-Allow-Origin. "
                    + ("Combined with Allow-Credentials: true, any website can make authenticated "
                       "API requests on behalf of logged-in users."
                       if acac.lower() == "true" else
                       "Any website can read API responses.")
                ),
                evidence=f"path={ep.path} origin={evil_origin} acao={acao} acac={acac}",
                affected=target,
                fingerprint=fp,
                confidence=0.98,
                cvss=9.1 if sev == "critical" else 7.5,
                remediation=(
                    f"[{sev.upper()} — OWASP API8:2023 Security Misconfiguration]\n\n"
                    f"[FIX] Validate Origin against a strict whitelist before reflecting.\n"
                    f"Never reflect arbitrary origins with Allow-Credentials: true."
                ),
                references=[_OWASP_API["API8"]],
            ))
            break  # One CORS finding is enough

        elif acao == "*":
            fp = stable_fingerprint(target, "api.scanner.config", "cors_wildcard", ep.path)
            findings.append(Finding(
                severity="medium",
                plugin_id="api.scanner.config",
                title=f"CORS wildcard (*) on API: {ep.method} {ep.path}",
                description="API returns Access-Control-Allow-Origin: * allowing any website to read responses.",
                evidence=f"path={ep.path} acao=*",
                affected=target,
                fingerprint=fp,
                confidence=1.0,
                remediation="[MEDIUM] Replace * with specific allowed origins for API endpoints.",
                references=[_OWASP_API["API8"]],
            ))
            break


async def _check_http_methods(client, endpoints, target, findings):
    """Check for unrestricted HTTP methods."""
    dangerous_methods = ["PUT", "DELETE", "PATCH"]

    for ep in endpoints[:15]:
        if ep.method not in ("GET", "POST"):
            continue

        # Try dangerous methods on GET/POST endpoints
        for method in dangerous_methods:
            resp = await client.request(method, ep.path)
            if resp.status in (200, 201, 204):
                fp = stable_fingerprint(target, "api.scanner.config", "method", ep.path, method)
                findings.append(Finding(
                    severity="medium",
                    plugin_id="api.scanner.config",
                    title=f"{method} method accepted on {ep.path} (defined as {ep.method})",
                    description=(
                        f"The endpoint {ep.path} accepts {method} requests even though the spec "
                        f"defines it as {ep.method} only. This may allow unintended modifications."
                    ),
                    evidence=f"path={ep.path} defined_method={ep.method} tested_method={method} status={resp.status}",
                    affected=target,
                    fingerprint=fp,
                    confidence=0.80,
                    remediation=(
                        f"[MEDIUM — OWASP API5:2023 Broken Function Level Authorization]\n\n"
                        f"[FIX] Restrict allowed HTTP methods per endpoint.\n"
                        f"Return 405 Method Not Allowed for unsupported methods."
                    ),
                    references=[_OWASP_API["API5"]],
                ))
                break  # One finding per endpoint


async def _check_verbose_errors(client, endpoints, target, findings):
    """Check for verbose error messages / stack traces."""
    # Send malformed input to trigger errors
    malformed_inputs = [
        "'", "{{", "${}", "<?xml", "NaN", "null",
        '{"__proto__": {}}', "[]", "' OR 1=1--",
    ]

    for ep in endpoints[:10]:
        if ep.method == "GET":
            for payload in malformed_inputs[:3]:
                first_param = ep.parameters[0].name if ep.parameters else "id"
                resp = await client.request("GET", ep.path, params={first_param: payload})

                if resp.status >= 400 and resp.body_length > 100:
                    for pattern in _ERROR_PATTERNS:
                        if re.search(pattern, resp.body, re.I):
                            fp = stable_fingerprint(target, "api.scanner.config", "verbose_error", ep.path)
                            findings.append(Finding(
                                severity="medium",
                                plugin_id="api.scanner.config",
                                title=f"Verbose error message: {ep.method} {ep.path}",
                                description=(
                                    f"The API returns detailed error information including stack traces "
                                    f"or internal paths. This helps attackers understand the technology stack."
                                ),
                                evidence=(
                                    f"path={ep.path} status={resp.status} "
                                    f"pattern={pattern} response_preview={resp.body[:300]}"
                                ),
                                affected=target,
                                fingerprint=fp,
                                confidence=0.90,
                                remediation=(
                                    f"[MEDIUM — OWASP API8:2023 Security Misconfiguration]\n\n"
                                    f"[FIX]\n"
                                    f"1. Disable debug mode in production\n"
                                    f"2. Return generic error messages to clients\n"
                                    f"3. Log detailed errors server-side only\n"
                                    f"4. Use error handling middleware"
                                ),
                                references=[_OWASP_API["API8"]],
                            ))
                            return  # One verbose error finding is enough


async def _check_rate_limiting(client, endpoints, target, findings):
    """Check for missing rate limiting."""
    # Find a suitable endpoint to test (prefer login/auth)
    test_ep = None
    for ep in endpoints:
        if any(kw in ep.path.lower() for kw in ["login", "auth", "token", "register"]):
            test_ep = ep
            break
    if not test_ep and endpoints:
        test_ep = endpoints[0]

    if not test_ep:
        return

    # Send 30 rapid requests
    rapid_count = 30
    tasks = []
    for _ in range(rapid_count):
        tasks.append(client.baseline_request(test_ep))

    responses = await asyncio.gather(*tasks, return_exceptions=True)

    statuses = []
    for r in responses:
        if isinstance(r, Exception):
            statuses.append(0)
        else:
            statuses.append(r.status)

    count_429 = statuses.count(429)
    count_403 = statuses.count(403)
    count_200 = sum(1 for s in statuses if s in (200, 201, 401))
    blocked = count_429 + count_403

    if blocked == 0 and count_200 > 20:
        fp = stable_fingerprint(target, "api.scanner.config", "no_rate_limit", test_ep.path)
        findings.append(Finding(
            severity="medium",
            plugin_id="api.scanner.config",
            title=f"No rate limiting on {test_ep.method} {test_ep.path}",
            description=(
                f"Sent {rapid_count} rapid requests. All {count_200} were processed without "
                f"throttling (0 blocked). An attacker can brute-force or abuse this endpoint."
            ),
            evidence=(
                f"path={test_ep.path} method={test_ep.method} "
                f"requests={rapid_count} allowed={count_200} blocked={blocked} "
                f"429s={count_429} 403s={count_403}"
            ),
            affected=target,
            fingerprint=fp,
            confidence=0.85,
            remediation=(
                f"[MEDIUM — OWASP API4:2023 Unrestricted Resource Consumption]\n\n"
                f"[FIX] Implement rate limiting:\n"
                f"  Express: app.use(rateLimit({{ windowMs: 60000, max: 100 }}))\n"
                f"  Nginx: limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;\n"
                f"  Django: django-ratelimit\n"
                f"  Spring: @RateLimiter annotation"
            ),
            references=[_OWASP_API["API4"]],
        ))


async def _check_exposed_docs(client, target, findings):
    """Check for exposed API documentation endpoints."""
    for path in _DOC_PATHS:
        resp = await client.request("GET", path)

        if resp.status == 200 and resp.body_length > 100:
            # Verify it's actual documentation, not a generic page
            doc_indicators = [
                "swagger", "openapi", "redoc", "graphiql", "actuator",
                "api-docs", "playground", "graphql", "prometheus",
                "metrics", "debug", "beans", "mappings",
            ]
            is_doc = any(ind in resp.body.lower()[:2000] for ind in doc_indicators)

            if is_doc:
                # Determine severity based on content
                sev = "medium"
                if "actuator" in path or "debug" in path or "trace" in path:
                    sev = "high"
                if "env" in path or "configprops" in path:
                    sev = "critical"

                fp = stable_fingerprint(target, "api.scanner.config", "exposed_docs", path)
                findings.append(Finding(
                    severity=sev,
                    plugin_id="api.scanner.config",
                    title=f"API documentation exposed: {path}",
                    description=(
                        f"The endpoint {path} is publicly accessible and exposes API documentation "
                        f"or internal service information. This reveals the full API attack surface."
                    ),
                    evidence=f"path={path} status={resp.status} size={resp.body_length}",
                    affected=target,
                    fingerprint=fp,
                    confidence=0.95,
                    remediation=(
                        f"[{sev.upper()} — OWASP API9:2023 Improper Inventory Management]\n\n"
                        f"[FIX]\n"
                        f"1. Disable documentation endpoints in production\n"
                        f"2. Require authentication to access API docs\n"
                        f"3. Use environment-based configuration:\n"
                        f"   if (process.env.NODE_ENV !== 'production') app.use('/docs', swaggerUI);\n"
                        f"4. Restrict access via IP allowlist or VPN"
                    ),
                    references=[_OWASP_API["API9"]],
                ))
