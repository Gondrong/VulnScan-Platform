"""
GraphQL Introspection & Security Scanner
Detects exposed GraphQL endpoints, introspection enabled, query depth issues,
and common GraphQL misconfigurations.
"""
import asyncio
import json
import re
import ssl
import urllib.parse

from app.scanner.plugins.base import Plugin, PluginMeta, PluginResult, Finding
from app.scanner.context import stable_fingerprint

META = PluginMeta(
    plugin_id="web.graphql_scanner",
    name="GraphQL Introspection & Security",
    category="web",
    depends_on=["fingerprint.http"],
    consumes=["fingerprint.http", "net.open_ports"],
    provides=["web.graphql_findings"],
    enabled_by_default=True,
    timeout_seconds=35.0,
)

# ── Common GraphQL endpoint paths ───────────────────────────────────────
_GRAPHQL_PATHS = [
    "/graphql",
    "/graphiql",
    "/api/graphql",
    "/api/v1/graphql",
    "/v1/graphql",
    "/v2/graphql",
    "/gql",
    "/query",
    "/graphql/console",
    "/altair",
    "/playground",
    "/explorer",
    "/graphql-explorer",
]

# ── Introspection query ─────────────────────────────────────────────────
_INTROSPECTION_QUERY = json.dumps({
    "query": """
    {
      __schema {
        queryType { name }
        mutationType { name }
        types {
          name
          kind
          fields {
            name
            type { name kind ofType { name kind } }
            args { name type { name kind } }
          }
        }
      }
    }
    """
})

# ── Simple query to detect GraphQL endpoint ─────────────────────────────
_DETECT_QUERY = json.dumps({"query": "{ __typename }"})

# ── Deep nesting query (test query depth limits) ────────────────────────
_DEEP_QUERY = json.dumps({
    "query": "{ __schema { types { fields { type { fields { type { fields { type { name } } } } } } } } }"
})

# ── Batch query (test batch limits) ─────────────────────────────────────
_BATCH_QUERY = json.dumps([
    {"query": "{ __typename }"},
    {"query": "{ __typename }"},
    {"query": "{ __typename }"},
    {"query": "{ __typename }"},
    {"query": "{ __typename }"},
])

# ── Sensitive type/field names to flag ──────────────────────────────────
_SENSITIVE_PATTERNS = [
    "password", "secret", "token", "credential", "apikey", "api_key",
    "private", "ssn", "credit_card", "creditcard", "cvv",
    "bank_account", "social_security", "auth_token", "refresh_token",
    "admin", "internal", "debug", "deleteall", "dropall",
    "seed_database", "reset_database", "execute_sql", "run_command",
]


async def _graphql_request(url: str, body: str, timeout: float = 8.0,
                           extra_headers: dict | None = None) -> tuple[int, str, dict]:
    """Send a GraphQL request and return (status, body, headers)."""
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"

    try:
        if parsed.scheme == "https":
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
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Content-Length": str(len(body)),
            "Connection": "close",
        }
        if extra_headers:
            headers.update(extra_headers)

        request = f"POST {path} HTTP/1.1\r\n"
        request += "".join(f"{k}: {v}\r\n" for k, v in headers.items())
        request += f"\r\n{body}"

        writer.write(request.encode())
        await writer.drain()

        response = await asyncio.wait_for(reader.read(131072), timeout=timeout)
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

        return status, resp_body, resp_headers
    except Exception:
        return 0, "", {}


def _is_graphql_response(body: str) -> bool:
    """Check if a response looks like a GraphQL response."""
    try:
        data = json.loads(body)
        return isinstance(data, dict) and ("data" in data or "errors" in data)
    except Exception:
        return False


def _extract_sensitive_fields(schema_data: dict) -> list[dict]:
    """Extract sensitive-looking types and fields from introspection result."""
    sensitive = []
    try:
        types = schema_data.get("data", {}).get("__schema", {}).get("types", [])
        for t in types:
            type_name = t.get("name", "")
            if type_name.startswith("__"):
                continue  # Skip internal types

            # Check type name
            for pattern in _SENSITIVE_PATTERNS:
                if pattern in type_name.lower():
                    sensitive.append({"type": type_name, "field": None, "pattern": pattern})
                    break

            # Check field names
            for f in (t.get("fields") or []):
                field_name = f.get("name", "")
                for pattern in _SENSITIVE_PATTERNS:
                    if pattern in field_name.lower():
                        sensitive.append({"type": type_name, "field": field_name, "pattern": pattern})
                        break
    except Exception:
        pass
    return sensitive


def _count_mutations(schema_data: dict) -> tuple[int, list[str]]:
    """Count and list mutation names from introspection."""
    mutations = []
    try:
        mutation_type_name = (
            schema_data.get("data", {}).get("__schema", {}).get("mutationType", {}) or {}
        ).get("name")
        if not mutation_type_name:
            return 0, []

        types = schema_data.get("data", {}).get("__schema", {}).get("types", [])
        for t in types:
            if t.get("name") == mutation_type_name:
                for f in (t.get("fields") or []):
                    mutations.append(f.get("name", ""))
                break
    except Exception:
        pass
    return len(mutations), mutations[:20]


class Check(Plugin):
    async def run(self, target: str, ctx) -> PluginResult:
        ports = ctx.get("net.open_ports", []) or []
        http_data = (ctx.get("fingerprint.http", {}) or {}).get("http", [])
        target_raw = ctx.get("target_raw", target)
        findings = []
        gql_results = []

        # ── Determine base URLs ────────────────────────────────────────
        base_urls = []
        if re.match(r"^https?://", target_raw, re.I):
            base_urls.append(target_raw.rstrip("/"))
        else:
            for item in http_data:
                url = item.get("url", "")
                if url:
                    base_urls.append(url.rstrip("/"))
            if not base_urls:
                web_ports = [p for p in ports if p in (80, 443, 8080, 8443, 3000, 5000, 8000)]
                for p in web_ports:
                    scheme = "https" if p in (443, 8443) else "http"
                    base_urls.append(f"{scheme}://{target}:{p}")

        if not base_urls:
            return PluginResult(artifacts={"web.graphql_findings": []})

        # ── Step 1: Discover GraphQL endpoints ─────────────────────────
        discovered_endpoints = []
        for base in base_urls[:2]:
            tasks = []
            for path in _GRAPHQL_PATHS:
                url = base + path
                tasks.append((url, _graphql_request(url, _DETECT_QUERY)))

            results = await asyncio.gather(
                *[t[1] for t in tasks], return_exceptions=True
            )

            for (url, _), result in zip(tasks, results):
                if isinstance(result, Exception):
                    continue
                status, body, headers = result
                if status in (200, 400) and _is_graphql_response(body):
                    discovered_endpoints.append(url)
                    gql_results.append({"endpoint": url, "status": "discovered"})

        if not discovered_endpoints:
            return PluginResult(artifacts={"web.graphql_findings": gql_results})

        # ── Step 2: Test introspection on each endpoint ────────────────
        for endpoint in discovered_endpoints[:3]:
            status, body, headers = await _graphql_request(endpoint, _INTROSPECTION_QUERY)

            if status != 200 or not body:
                continue

            try:
                schema_data = json.loads(body)
            except Exception:
                continue

            if not schema_data.get("data", {}).get("__schema"):
                continue

            # Introspection is enabled
            schema = schema_data["data"]["__schema"]
            type_count = len(schema.get("types", []))
            mutation_count, mutation_names = _count_mutations(schema_data)
            query_type = (schema.get("queryType") or {}).get("name", "unknown")

            fp = stable_fingerprint(target, META.plugin_id, "introspection", endpoint)
            findings.append(Finding(
                severity="medium",
                plugin_id=META.plugin_id,
                title=f"GraphQL introspection enabled at {_short_path(endpoint)}",
                description=(
                    f"GraphQL introspection is enabled at {endpoint}, exposing the full API schema "
                    f"({type_count} types, {mutation_count} mutations). Attackers can map the entire "
                    f"API surface without guessing endpoints."
                ),
                evidence=(
                    f"url={endpoint} types={type_count} mutations={mutation_count} "
                    f"query_type={query_type} mutation_names={mutation_names[:10]}"
                ),
                affected=target,
                fingerprint=fp,
                confidence=1.0,
                remediation=(
                    f"[AFFECTED] GraphQL introspection is enabled at {endpoint}\n\n"
                    f"[SCHEMA STATS] {type_count} types, {mutation_count} mutations\n\n"
                    f"[FIX] Disable introspection in production:\n"
                    f"  Apollo Server: introspection: false\n"
                    f"  graphql-yoga: maskedErrors + disableIntrospection: true\n"
                    f"  Django Graphene: GRAPHENE = {{'MIDDLEWARE': ['graphql_utils.DisableIntrospection']}}\n"
                    f"  Spring GraphQL: graphql.servlet.introspection.enabled=false\n\n"
                    f"[NOTE] Keep introspection enabled in development environments only."
                ),
                references=[
                    "https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/",
                    "https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
                ],
            ))
            gql_results.append({"endpoint": endpoint, "introspection": True, "types": type_count, "mutations": mutation_count})

            # ── Check 2a: Sensitive fields exposed ─────────────────────
            sensitive = _extract_sensitive_fields(schema_data)
            if sensitive:
                sensitive_summary = [
                    f"{s['type']}.{s['field']}" if s['field'] else s['type']
                    for s in sensitive[:10]
                ]
                fp = stable_fingerprint(target, META.plugin_id, "sensitive_fields", endpoint)
                findings.append(Finding(
                    severity="high",
                    plugin_id=META.plugin_id,
                    title=f"GraphQL schema exposes {len(sensitive)} sensitive field(s)",
                    description=(
                        f"The GraphQL schema at {endpoint} contains fields with sensitive names: "
                        f"{', '.join(sensitive_summary)}. These may expose internal data or "
                        f"dangerous operations."
                    ),
                    evidence=f"url={endpoint} sensitive_fields={sensitive[:15]}",
                    affected=target,
                    fingerprint=fp,
                    confidence=0.80,
                    remediation=(
                        f"[AFFECTED] Sensitive fields in GraphQL schema:\n"
                        f"{chr(10).join('  - ' + s for s in sensitive_summary)}\n\n"
                        f"[FIX]\n"
                        f"1. Remove sensitive fields from the public schema\n"
                        f"2. Use field-level authorization (@auth directives)\n"
                        f"3. Implement query allowlisting (persisted queries)\n"
                        f"4. Apply role-based access control per resolver"
                    ),
                    references=["https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html"],
                ))

            # ── Check 2b: Dangerous mutations ──────────────────────────
            dangerous_mutations = [
                m for m in mutation_names
                if any(d in m.lower() for d in [
                    "delete_all", "drop", "reset", "seed", "execute", "run_command",
                    "admin_", "system_", "internal_", "debug_",
                ])
            ]
            if dangerous_mutations:
                fp = stable_fingerprint(target, META.plugin_id, "dangerous_mutations", endpoint)
                findings.append(Finding(
                    severity="high",
                    plugin_id=META.plugin_id,
                    title=f"GraphQL exposes {len(dangerous_mutations)} dangerous mutation(s)",
                    description=(
                        f"The GraphQL schema at {endpoint} contains mutations that appear to be "
                        f"administrative or destructive: {', '.join(dangerous_mutations)}"
                    ),
                    evidence=f"url={endpoint} dangerous_mutations={dangerous_mutations}",
                    affected=target,
                    fingerprint=fp,
                    confidence=0.75,
                    remediation=(
                        f"[AFFECTED] Dangerous mutations exposed:\n"
                        f"{chr(10).join('  - ' + m for m in dangerous_mutations)}\n\n"
                        f"[FIX]\n"
                        f"1. Move admin mutations to a separate schema/endpoint\n"
                        f"2. Require admin authentication for these mutations\n"
                        f"3. Implement mutation allowlisting\n"
                        f"4. Add rate limiting to destructive operations"
                    ),
                    references=["https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html"],
                ))

        # ── Step 3: Test query depth limit ─────────────────────────────
        for endpoint in discovered_endpoints[:2]:
            status, body, _ = await _graphql_request(endpoint, _DEEP_QUERY)
            if status == 200 and _is_graphql_response(body):
                try:
                    data = json.loads(body)
                    if data.get("data") and not data.get("errors"):
                        fp = stable_fingerprint(target, META.plugin_id, "no_depth_limit", endpoint)
                        findings.append(Finding(
                            severity="medium",
                            plugin_id=META.plugin_id,
                            title=f"No GraphQL query depth limit at {_short_path(endpoint)}",
                            description=(
                                f"The GraphQL endpoint at {endpoint} accepts deeply nested queries "
                                f"without restriction. This enables denial-of-service via recursive queries."
                            ),
                            evidence=f"url={endpoint} deep_query_accepted=true",
                            affected=target,
                            fingerprint=fp,
                            confidence=0.85,
                            remediation=(
                                f"[AFFECTED] No query depth limit at {endpoint}\n\n"
                                f"[FIX] Implement query depth limiting:\n"
                                f"  Apollo: depthLimit(10) validation rule\n"
                                f"  graphql-js: createComplexityValidator({{maxDepth: 10}})\n"
                                f"  graphql-ruby: max_depth 10\n\n"
                                f"[ALSO CONSIDER]\n"
                                f"  - Query cost analysis / complexity limiting\n"
                                f"  - Timeout per query execution\n"
                                f"  - Rate limiting per client"
                            ),
                            references=["https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html"],
                        ))
                except Exception:
                    pass

        # ── Step 4: Test batch query abuse ─────────────────────────────
        for endpoint in discovered_endpoints[:2]:
            status, body, _ = await _graphql_request(endpoint, _BATCH_QUERY)
            if status == 200:
                try:
                    data = json.loads(body)
                    if isinstance(data, list) and len(data) >= 5:
                        fp = stable_fingerprint(target, META.plugin_id, "batch_unlimited", endpoint)
                        findings.append(Finding(
                            severity="low",
                            plugin_id=META.plugin_id,
                            title=f"GraphQL batch queries accepted at {_short_path(endpoint)}",
                            description=(
                                f"The GraphQL endpoint at {endpoint} accepts batch queries without "
                                f"limit. An attacker can send hundreds of queries in a single request "
                                f"to bypass rate limiting or perform brute-force attacks."
                            ),
                            evidence=f"url={endpoint} batch_size=5 all_succeeded=true",
                            affected=target,
                            fingerprint=fp,
                            confidence=0.85,
                            remediation=(
                                f"[AFFECTED] Unlimited batch queries at {endpoint}\n\n"
                                f"[FIX] Limit batch query size:\n"
                                f"  Apollo: allowBatchedHttpRequests: false (or set max)\n"
                                f"  graphql-yoga: batching: {{limit: 5}}\n\n"
                                f"[ALSO] Implement per-query cost analysis to prevent abuse."
                            ),
                            references=["https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html"],
                        ))
                except Exception:
                    pass

        return PluginResult(
            findings=findings,
            artifacts={"web.graphql_findings": gql_results},
        )


def _short_path(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    return parsed.path or "/"

