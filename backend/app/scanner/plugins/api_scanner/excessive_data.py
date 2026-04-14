"""
API Excessive Data Exposure Scanner — OWASP API3:2023
(formerly API6:2019 Excessive Data Exposure)

Two complementary heuristics:
1. Sensitive-key detection — GET each endpoint and walk the JSON
   response for fields whose names match well-known secret/PII
   patterns (password, *_hash, ssn, credit_card, private_key,
   *_token, internal_*, cvv). A single hit produces a high-severity
   finding because it indicates the API is shipping data that
   should never leave the trust boundary.
2. Schema-drift detection — when the spec declares a schema for
   the response body, compare the actual response field count
   against the declared property count. A response with >2× more
   fields than declared signals an underspecified contract that
   often hides incidental disclosures.
"""
import json
import logging
import re

from app.scanner.plugins.base import Finding
from app.scanner.context import stable_fingerprint

logger = logging.getLogger("vulnscan.api_scanner.excessive_data")

_MAX_ENDPOINTS = 30

# Field-name patterns that should never appear in a public response.
_SENSITIVE_PATTERNS = [
    (re.compile(r"^password.*$", re.I), "credential"),
    (re.compile(r".*_hash$", re.I), "credential"),
    (re.compile(r"^password_hash$", re.I), "credential"),
    (re.compile(r"^secret.*$", re.I), "credential"),
    (re.compile(r".*api[_-]?key$", re.I), "credential"),
    (re.compile(r".*_token$", re.I), "credential"),
    (re.compile(r"^refresh_token$", re.I), "credential"),
    (re.compile(r"^private_key$", re.I), "credential"),
    (re.compile(r"^ssh_key$", re.I), "credential"),
    (re.compile(r"^ssn$", re.I), "pii"),
    (re.compile(r"^social_security.*$", re.I), "pii"),
    (re.compile(r".*credit_card.*", re.I), "pii"),
    (re.compile(r"^cvv$", re.I), "pii"),
    (re.compile(r"^iban$", re.I), "pii"),
    (re.compile(r"^date_of_birth$", re.I), "pii"),
    (re.compile(r"^dob$", re.I), "pii"),
    (re.compile(r"^internal_.*", re.I), "internal"),
    (re.compile(r"^__.*", re.I), "internal"),
    (re.compile(r"^debug_.*", re.I), "internal"),
]


def _walk_keys(obj, path=""):
    """Yield (dotted_path, value) for every leaf-or-dict key in JSON."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            cur = f"{path}.{k}" if path else k
            yield (k, cur, v)
            if isinstance(v, (dict, list)):
                yield from _walk_keys(v, cur)
    elif isinstance(obj, list):
        for i, v in enumerate(obj[:10]):
            yield from _walk_keys(v, f"{path}[{i}]")


def _scan_response_for_sensitive(body: str) -> list[tuple[str, str, str]]:
    """Return list of (key, dotted_path, category) hits."""
    hits: list[tuple[str, str, str]] = []
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return hits
    seen_keys: set[str] = set()
    count = 0
    for key, dotted, _ in _walk_keys(data):
        count += 1
        if count > 800:
            break
        for pat, cat in _SENSITIVE_PATTERNS:
            if pat.match(key):
                if dotted not in seen_keys:
                    seen_keys.add(dotted)
                    hits.append((key, dotted, cat))
                break
    return hits


def _count_response_fields(body: str) -> int:
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return 0
    if isinstance(data, list) and data:
        data = data[0]
    if not isinstance(data, dict):
        return 0
    return len(data)


def _declared_field_count(ep) -> int:
    """Count of body fields declared on the endpoint via spec parsing."""
    return sum(1 for p in ep.parameters if p.location == "body")


async def check(client, endpoints, ctx) -> list[Finding]:
    findings = []
    target = ctx.get("target_raw", "unknown")
    seen_fps: set[str] = set()

    candidates = [ep for ep in endpoints if ep.method == "GET"][:_MAX_ENDPOINTS]

    for ep in candidates:
        # Build a request — replace path params with example or "1"
        path = ep.path
        for p in ep.parameters:
            if p.location == "path" and f"{{{p.name}}}" in path:
                val = (p.example or "1")
                path = path.replace(f"{{{p.name}}}", val)
        params = {p.name: (p.example or "1")
                  for p in ep.parameters if p.location == "query"}

        try:
            resp = await client.request("GET", path, params=params or None)
        except Exception as e:
            logger.debug("Excessive-data probe failed for %s: %s", ep.path, e)
            continue

        if resp.status != 200 or not resp.body:
            continue

        # 1) Sensitive-key sweep
        hits = _scan_response_for_sensitive(resp.body)
        if hits:
            categories = sorted({c for _, _, c in hits})
            sev = "high" if "credential" in categories or "pii" in categories else "medium"
            cvss = 7.5 if sev == "high" else 5.3
            fp = stable_fingerprint(target, "api.scanner.excessive_data",
                                    "sensitive", ep.path)
            if fp not in seen_fps:
                seen_fps.add(fp)
                shown = ", ".join(f"{k}@{p}" for k, p, _ in hits[:6])
                findings.append(Finding(
                    severity=sev,
                    plugin_id="api.scanner.excessive_data",
                    title=f"Sensitive fields in response: GET {ep.path}",
                    description=(
                        f"Response from GET {ep.path} contains {len(hits)} field(s) "
                        f"matching sensitive patterns ({', '.join(categories)}). "
                        "Returning credentials, PII, or internal markers from a "
                        "list/detail endpoint is the OWASP API3:2023 (Excessive "
                        "Data Exposure) anti-pattern: clients receive more than "
                        "they need and the surplus becomes a leak."
                    ),
                    evidence=(
                        f"path={ep.path} status=200 hits={len(hits)} "
                        f"categories={categories} samples={shown}"
                    ),
                    affected=target,
                    fingerprint=fp,
                    confidence=0.9,
                    cvss=cvss,
                    remediation=(
                        "[HIGH — OWASP API3:2023]\n\n"
                        "[FIX]\n"
                        "  • Project responses through an explicit serializer / DTO\n"
                        "  • Never serialize ORM objects directly\n"
                        "  • Add CI checks asserting response schemas omit secret fields\n"
                        "  • Use field-level @JsonIgnore / exclude lists for credentials"
                    ),
                    references=[
                        "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/",
                    ],
                ))

        # 2) Schema-drift heuristic
        declared = _declared_field_count(ep)
        actual = _count_response_fields(resp.body)
        if declared > 0 and actual > declared * 2 and actual >= 6:
            fp = stable_fingerprint(target, "api.scanner.excessive_data",
                                    "schema_drift", ep.path)
            if fp not in seen_fps:
                seen_fps.add(fp)
                findings.append(Finding(
                    severity="medium",
                    plugin_id="api.scanner.excessive_data",
                    title=f"Response exceeds declared schema: GET {ep.path}",
                    description=(
                        f"Response object contains {actual} top-level fields, but "
                        f"the spec declares only {declared}. The API is returning "
                        "more data than its contract documents — an under-specified "
                        "schema commonly hides incidental disclosures."
                    ),
                    evidence=(
                        f"path={ep.path} declared_fields={declared} "
                        f"actual_fields={actual}"
                    ),
                    affected=target,
                    fingerprint=fp,
                    confidence=0.65,
                    cvss=4.3,
                    remediation=(
                        "[MEDIUM] Tighten the response schema in the spec, then "
                        "filter the serializer to match. Run contract tests in CI."
                    ),
                ))

    return findings
