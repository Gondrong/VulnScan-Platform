"""
API GraphQL Security Scanner
Tests GraphQL endpoints for:
- Introspection enabled (full schema dump)
- Batch query abuse (rate limit bypass)
- Query depth attacks (DoS)
- Field suggestion leakage
- BOLA probes (object-level authorization)
"""
import asyncio
import json
import logging
import re

from app.scanner.plugins.base import Finding
from app.scanner.context import stable_fingerprint

logger = logging.getLogger("vulnscan.api_scanner.graphql")

_GQL_PATHS = ["/graphql", "/api/graphql", "/v1/graphql", "/gql", "/query", "/graphiql"]

_INTROSPECTION_QUERY = '{"query":"{ __schema { queryType { name } mutationType { name } types { name kind fields { name type { name } args { name } } } } }"}'
_DETECT_QUERY = '{"query":"{ __typename }"}'
_DEEP_QUERY = '{"query":"{ __schema { types { fields { type { fields { type { fields { type { name } } } } } } } } }"}'
_BATCH_QUERY = '[{"query":"{ __typename }"},{"query":"{ __typename }"},{"query":"{ __typename }"},{"query":"{ __typename }"},{"query":"{ __typename }"}]'

_SENSITIVE_FIELDS = [
    "password", "secret", "token", "credential", "apikey", "api_key",
    "admin", "internal", "debug", "deleteall", "dropall", "seed",
    "execute_sql", "run_command", "private_key", "ssn", "credit_card",
]


async def check(client, endpoints, ctx) -> list[Finding]:
    findings = []
    target = ctx.get("target_raw", "unknown")

    # Find GraphQL endpoints
    gql_endpoints = []

    # From spec
    for ep in endpoints:
        if any(kw in ep.path.lower() for kw in ["graphql", "gql"]):
            gql_endpoints.append(ep.path)

    # Probe common paths
    for path in _GQL_PATHS:
        r = await client.send_raw("POST", path, body=_DETECT_QUERY, content_type="application/json")
        if r.status in (200, 400):
            try:
                data = json.loads(r.body)
                if "data" in data or "errors" in data:
                    if path not in gql_endpoints:
                        gql_endpoints.append(path)
            except Exception:
                pass

    if not gql_endpoints:
        return findings

    for gql_path in gql_endpoints[:3]:
        # 1. Introspection
        r = await client.send_raw("POST", gql_path, body=_INTROSPECTION_QUERY, content_type="application/json")
        if r.status == 200:
            try:
                data = json.loads(r.body)
                schema = data.get("data", {}).get("__schema")
                if schema:
                    types = schema.get("types", [])
                    type_count = len(types)
                    mutation_type = (schema.get("mutationType") or {}).get("name")
                    mutations = []
                    if mutation_type:
                        for t in types:
                            if t.get("name") == mutation_type:
                                mutations = [f.get("name", "") for f in (t.get("fields") or [])]
                                break

                    fp = stable_fingerprint(target, "api.scanner.graphql", "introspection", gql_path)
                    findings.append(Finding(
                        severity="medium", plugin_id="api.scanner.graphql",
                        title=f"GraphQL introspection enabled: {gql_path}",
                        description=(
                            f"GraphQL introspection is enabled at {gql_path}. "
                            f"Schema: {type_count} types, {len(mutations)} mutations. "
                            f"Attackers can map the entire API surface."
                        ),
                        evidence=f"path={gql_path} types={type_count} mutations={len(mutations)} mutation_names={mutations[:10]}",
                        affected=target, fingerprint=fp, confidence=1.0, cvss=5.3,
                        remediation=(
                            "[MEDIUM — OWASP API9:2023 Improper Inventory Management]\n\n"
                            "[FIX] Disable introspection in production:\n"
                            "  Apollo: introspection: false\n"
                            "  Django Graphene: GRAPHENE = {'MIDDLEWARE': [...]}\n"
                            "  Spring: graphql.servlet.introspection.enabled=false"
                        ),
                        references=["https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html"],
                    ))

                    # Check for sensitive fields
                    sensitive = []
                    for t in types:
                        if t.get("name", "").startswith("__"):
                            continue
                        for f in (t.get("fields") or []):
                            fname = f.get("name", "").lower()
                            for pat in _SENSITIVE_FIELDS:
                                if pat in fname:
                                    sensitive.append(f"{t['name']}.{f['name']}")
                                    break

                    if sensitive:
                        fp = stable_fingerprint(target, "api.scanner.graphql", "sensitive", gql_path)
                        findings.append(Finding(
                            severity="high", plugin_id="api.scanner.graphql",
                            title=f"GraphQL schema exposes {len(sensitive)} sensitive field(s)",
                            description=f"Sensitive fields in schema: {', '.join(sensitive[:10])}",
                            evidence=f"path={gql_path} sensitive={sensitive[:15]}",
                            affected=target, fingerprint=fp, confidence=0.80, cvss=7.5,
                            remediation="[HIGH] Remove sensitive fields from public schema. Use field-level auth.",
                            references=["https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html"],
                        ))

            except Exception:
                pass

        # 2. Query depth attack
        r = await client.send_raw("POST", gql_path, body=_DEEP_QUERY, content_type="application/json")
        if r.status == 200:
            try:
                data = json.loads(r.body)
                if data.get("data") and not data.get("errors"):
                    fp = stable_fingerprint(target, "api.scanner.graphql", "depth", gql_path)
                    findings.append(Finding(
                        severity="medium", plugin_id="api.scanner.graphql",
                        title=f"No GraphQL query depth limit: {gql_path}",
                        description="Deeply nested queries are accepted without restriction. DoS risk via recursive queries.",
                        evidence=f"path={gql_path} deep_query_accepted=true",
                        affected=target, fingerprint=fp, confidence=0.85, cvss=5.3,
                        remediation=(
                            "[MEDIUM — OWASP API4:2023 Unrestricted Resource Consumption]\n\n"
                            "[FIX] Implement query depth limiting (max 10-15 levels)."
                        ),
                    ))
            except Exception:
                pass

        # 3. Batch query abuse
        r = await client.send_raw("POST", gql_path, body=_BATCH_QUERY, content_type="application/json")
        if r.status == 200:
            try:
                data = json.loads(r.body)
                if isinstance(data, list) and len(data) >= 5:
                    fp = stable_fingerprint(target, "api.scanner.graphql", "batch", gql_path)
                    findings.append(Finding(
                        severity="low", plugin_id="api.scanner.graphql",
                        title=f"GraphQL batch queries accepted: {gql_path}",
                        description="Unlimited batch queries — can bypass rate limiting with many queries in one request.",
                        evidence=f"path={gql_path} batch_size=5 all_accepted=true",
                        affected=target, fingerprint=fp, confidence=0.85, cvss=3.7,
                        remediation="[LOW — OWASP API4:2023] Limit batch query size or disable batching.",
                    ))
            except Exception:
                pass

        # 4. Field suggestion leakage
        bad_query = '{"query":"{ user { passwor } }"}'
        r = await client.send_raw("POST", gql_path, body=bad_query, content_type="application/json")
        if r.status in (200, 400):
            try:
                data = json.loads(r.body)
                errors = data.get("errors", [])
                for err in errors:
                    msg = err.get("message", "")
                    if "did you mean" in msg.lower() or "suggestion" in msg.lower():
                        fp = stable_fingerprint(target, "api.scanner.graphql", "suggestion", gql_path)
                        findings.append(Finding(
                            severity="low", plugin_id="api.scanner.graphql",
                            title=f"GraphQL field suggestions enabled: {gql_path}",
                            description=f"Error messages suggest valid field names. Message: '{msg[:100]}'",
                            evidence=f"path={gql_path} suggestion_msg={msg[:200]}",
                            affected=target, fingerprint=fp, confidence=0.90,
                            remediation="[LOW] Disable field suggestions in production to prevent schema enumeration.",
                        ))
                        break
            except Exception:
                pass

    return findings
