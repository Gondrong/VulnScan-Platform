"""
API Broken Object-Level Authorization (BOLA / IDOR) Scanner — OWASP API1:2023

Strategy:
1. If a secondary identity is configured on the HTTP client, fetch each
   object-bearing endpoint with both identities and compare responses.
   Two distinct users receiving the same record body is the canonical
   BOLA signature.
2. If no secondary identity is available, fall back to numeric ID
   neighbour-walking with the primary identity. Adjacent IDs returning
   200 with substantive bodies indicate weak/absent authorization on
   listing or per-object endpoints.

Heuristics are tuned to keep false positives low:
- Only endpoints with an object-identifier-shaped param are probed.
- Comparisons require non-trivial bodies (>200 bytes) and a high JSON
  key Jaccard similarity (>0.8) before a finding is emitted.
- Findings include the path, parameter, status pair, and similarity score.
"""
import asyncio
import json
import logging
import re

from app.scanner.plugins.base import Finding
from app.scanner.context import stable_fingerprint

logger = logging.getLogger("vulnscan.api_scanner.bola")

# Parameter names that suggest a per-object identifier
_ID_PARAM_RE = re.compile(
    r"(^|_)(id|uuid|guid|user(_?id)?|account(_?id)?|order(_?id)?|"
    r"customer(_?id)?|profile(_?id)?|object(_?id)?|item(_?id)?)$",
    re.I,
)

_MAX_ENDPOINTS = 25
_MIN_BODY = 200
_SIMILARITY_THRESHOLD = 0.8


def _is_id_param(name: str) -> bool:
    return bool(_ID_PARAM_RE.search(name or ""))


def _extract_json_keys(body: str) -> set[str]:
    """Recursively collect JSON keys from a response body, capped for safety."""
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return set()

    keys: set[str] = set()
    stack = [data]
    seen = 0
    while stack and seen < 500:
        cur = stack.pop()
        seen += 1
        if isinstance(cur, dict):
            for k, v in cur.items():
                keys.add(str(k))
                if isinstance(v, (dict, list)):
                    stack.append(v)
        elif isinstance(cur, list):
            for v in cur[:20]:
                if isinstance(v, (dict, list)):
                    stack.append(v)
    return keys


def _jaccard(a: set, b: set) -> float:
    if not a and not b:
        return 0.0
    inter = len(a & b)
    union = len(a | b)
    return inter / union if union else 0.0


async def check(client, endpoints, ctx) -> list[Finding]:
    findings = []
    target = ctx.get("target_raw", "unknown")

    has_secondary = getattr(client, "has_secondary_auth", False)
    candidates = []
    for ep in endpoints:
        if ep.method not in ("GET", "PUT", "PATCH", "DELETE"):
            continue
        for p in ep.parameters:
            if p.location in ("path", "query") and _is_id_param(p.name):
                candidates.append((ep, p))
                break

    if not candidates:
        return findings

    for ep, param in candidates[:_MAX_ENDPOINTS]:
        try:
            if has_secondary:
                await _check_with_two_identities(client, ep, param, target, findings)
            else:
                await _check_neighbor_walk(client, ep, param, target, findings)
        except Exception as e:
            logger.debug("BOLA probe failed for %s: %s", ep.path, e)

    return findings


async def _check_with_two_identities(client, ep, param, target, findings):
    """Compare same-object response under primary vs secondary identity."""
    # Use the param's example value if present, else a benign default
    sample = (param.example or "1").strip()
    if not sample:
        sample = "1"

    # Build the path + params for this probe
    if param.location == "path":
        path_a = ep.path.replace(f"{{{param.name}}}", sample)
        params_a = None
    else:
        path_a = ep.path
        params_a = {param.name: sample}

    resp_a = await client.request_as("primary", ep.method, path_a, params=params_a)
    resp_b = await client.request_as("secondary", ep.method, path_a, params=params_a)

    # Both must succeed and return substantive bodies
    if resp_a.status != 200 or resp_b.status != 200:
        return
    if resp_a.body_length < _MIN_BODY or resp_b.body_length < _MIN_BODY:
        return

    keys_a = _extract_json_keys(resp_a.body)
    keys_b = _extract_json_keys(resp_b.body)
    sim = _jaccard(keys_a, keys_b)
    if sim < _SIMILARITY_THRESHOLD:
        return

    fp = stable_fingerprint(target, "api.scanner.bola", "two_identity",
                            ep.path, param.name)
    findings.append(Finding(
        severity="critical",
        plugin_id="api.scanner.bola",
        title=f"BOLA confirmed: {ep.method} {ep.path} accessible by two identities",
        description=(
            f"Endpoint {ep.method} {ep.path} returned a substantive response (200) "
            f"to two distinct authenticated identities for the same object id "
            f"({param.name}={sample}). JSON-key Jaccard similarity: {sim:.2f}. "
            "This is a textbook OWASP API1 (Broken Object-Level Authorization) "
            "violation — the server is not checking that the caller owns the object."
        ),
        evidence=(
            f"path={ep.path} method={ep.method} param={param.name} value={sample} "
            f"primary_status={resp_a.status} secondary_status={resp_b.status} "
            f"primary_len={resp_a.body_length} secondary_len={resp_b.body_length} "
            f"key_similarity={sim:.2f}"
        ),
        affected=target,
        fingerprint=fp,
        confidence=0.85,
        cvss=8.6,
        remediation=(
            "[CRITICAL — OWASP API1:2023 Broken Object-Level Authorization]\n\n"
            "[FIX] Enforce per-object authorization in the handler:\n"
            "  • Check the object's owner against the authenticated subject\n"
            "    BEFORE returning data (e.g. WHERE id=:id AND owner_id=:user)\n"
            "  • Prefer opaque identifiers (UUIDs) over sequential integers\n"
            "  • Centralize authorization in middleware/policies, not ad-hoc per route"
        ),
        references=[
            "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
        ],
    ))


async def _check_neighbor_walk(client, ep, param, target, findings):
    """Without a secondary identity, walk numeric neighbours of the example id."""
    base = (param.example or "1").strip()
    if not base.isdigit():
        return  # Only attempt enumeration on numeric IDs
    base_int = int(base)
    neighbours = [base_int + 1, base_int - 1, base_int + 5]
    neighbours = [n for n in neighbours if n > 0 and n != base_int]

    successes = 0
    samples = []
    for n in neighbours:
        sample = str(n)
        if param.location == "path":
            path = ep.path.replace(f"{{{param.name}}}", sample)
            params = None
        else:
            path = ep.path
            params = {param.name: sample}
        resp = await client.request(ep.method, path, params=params)
        if resp.status == 200 and resp.body_length >= _MIN_BODY:
            successes += 1
            samples.append((sample, resp.status, resp.body_length))
        await asyncio.sleep(0)  # cooperative yield

    if successes >= 2:
        fp = stable_fingerprint(target, "api.scanner.bola", "neighbour_walk",
                                ep.path, param.name)
        findings.append(Finding(
            severity="high",
            plugin_id="api.scanner.bola",
            title=f"Potential IDOR via ID enumeration: {ep.method} {ep.path}",
            description=(
                f"Sequential identifiers around {param.name}={base} returned 200 "
                f"with substantive bodies under a single identity. This suggests "
                f"missing per-object authorization. Configure a second user "
                f"identity to confirm BOLA."
            ),
            evidence=(
                f"path={ep.path} method={ep.method} param={param.name} "
                f"base={base} hits={samples}"
            ),
            affected=target,
            fingerprint=fp,
            confidence=0.55,
            cvss=7.5,
            remediation=(
                "[HIGH — OWASP API1:2023]\n\n"
                "[FIX] Verify per-object authorization (owner_id check) and "
                "switch to opaque IDs (UUIDs) for user-facing identifiers."
            ),
            references=[
                "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
            ],
        ))
