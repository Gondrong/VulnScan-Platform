"""
API Mass Assignment / BOPLA Scanner — OWASP API3:2023

Tests POST/PUT/PATCH endpoints with JSON bodies for over-permissive
input binding. The scanner submits the legitimate body augmented with
sensitive properties not declared in the spec (is_admin, role, balance,
etc.). When the server accepts the request and echoes the injected
property in the response, this confirms the API is binding arbitrary
client input to internal models — the BOPLA pattern.

Probes are scoped to body parameters and capped per scan to keep impact
on the target predictable.
"""
import json
import logging

from app.scanner.plugins.base import Finding
from app.scanner.context import stable_fingerprint

logger = logging.getLogger("vulnscan.api_scanner.mass_assignment")

_MAX_ENDPOINTS = 20

# (field, value, severity_hint) — value chosen to be detectable in echoes
_INJECTIONS = [
    ("is_admin", True, "critical"),
    ("isAdmin", True, "critical"),
    ("admin", True, "critical"),
    ("role", "admin", "critical"),
    ("user_role", "admin", "critical"),
    ("verified", True, "high"),
    ("email_verified", True, "high"),
    ("account_balance", 999999, "high"),
    ("balance", 999999, "high"),
    ("credits", 999999, "high"),
]


def _build_baseline_body(ep) -> dict:
    body = {}
    for p in ep.parameters:
        if p.location != "body":
            continue
        if p.example is not None and p.example != "":
            body[p.name] = p.example
        elif p.param_type == "integer":
            body[p.name] = 1
        elif p.param_type == "boolean":
            body[p.name] = False
        else:
            body[p.name] = "test"
    return body


def _value_present_in_response(body: str, field: str, value) -> bool:
    """True if the injected field/value pair appears in the response JSON."""
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return False

    target_value = value
    stack = [data]
    seen = 0
    while stack and seen < 500:
        cur = stack.pop()
        seen += 1
        if isinstance(cur, dict):
            if field in cur and cur[field] == target_value:
                return True
            for v in cur.values():
                if isinstance(v, (dict, list)):
                    stack.append(v)
        elif isinstance(cur, list):
            for v in cur[:20]:
                if isinstance(v, (dict, list)):
                    stack.append(v)
    return False


async def check(client, endpoints, ctx) -> list[Finding]:
    findings = []
    target = ctx.get("target_raw", "unknown")

    candidates = [
        ep for ep in endpoints
        if ep.method in ("POST", "PUT", "PATCH")
        and any(p.location == "body" for p in ep.parameters)
    ]
    if not candidates:
        return findings

    declared_fields_by_ep = {
        id(ep): {p.name for p in ep.parameters if p.location == "body"}
        for ep in candidates
    }

    seen_fps = set()
    for ep in candidates[:_MAX_ENDPOINTS]:
        baseline = _build_baseline_body(ep)
        declared = declared_fields_by_ep[id(ep)]

        for field, value, sev_hint in _INJECTIONS:
            if field in declared:
                continue  # already a legitimate field — skip
            payload = dict(baseline)
            payload[field] = value
            try:
                resp = await client.send_raw(ep.method, ep.path, body=payload)
            except Exception as e:
                logger.debug("Mass-assignment probe failed: %s", e)
                continue

            if resp.status not in (200, 201, 202):
                continue
            if not _value_present_in_response(resp.body, field, value):
                continue

            fp = stable_fingerprint(target, "api.scanner.mass_assignment",
                                    ep.path, field)
            if fp in seen_fps:
                continue
            seen_fps.add(fp)

            findings.append(Finding(
                severity=sev_hint,
                plugin_id="api.scanner.mass_assignment",
                title=f"Mass assignment: {ep.method} {ep.path} accepts '{field}'",
                description=(
                    f"Endpoint {ep.method} {ep.path} accepted an undeclared "
                    f"property '{field}={value!r}' and the value was reflected "
                    "in the response. The server is binding arbitrary client "
                    "input to its model (OWASP API3:2023, Broken Object "
                    "Property Level Authorization)."
                ),
                evidence=(
                    f"path={ep.path} method={ep.method} injected={field}={value!r} "
                    f"status={resp.status} echoed=true"
                ),
                affected=target,
                fingerprint=fp,
                confidence=0.85,
                cvss=8.1 if sev_hint == "critical" else 7.5,
                remediation=(
                    "[HIGH — OWASP API3:2023 Broken Object Property Level Auth.]\n\n"
                    "[FIX]\n"
                    "  • Use an allow-list (DTO / serializer field whitelist) for body binding\n"
                    "  • Never bind requests directly to ORM models\n"
                    "  • Reject unknown properties (most JSON parsers / validators support strict mode)\n"
                    "  • Restrict sensitive flags (role, is_admin, balance) to admin-only endpoints"
                ),
                references=[
                    "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/",
                ],
            ))
            break  # one finding per endpoint is enough

    return findings
