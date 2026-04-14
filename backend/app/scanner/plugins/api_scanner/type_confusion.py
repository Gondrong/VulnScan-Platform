"""
API Type Confusion / Parameter Pollution Scanner

Submits values that violate each parameter's declared type
(integer, boolean, string) and looks for either:
  • a 5xx response — the framework crashed because the value was
    not coerced safely, indicating unhandled types reach the model
  • a substantively different 200 body length compared to the
    typed baseline — indicates the server silently accepts wrong
    types and behaviour diverges, often the entry-point for NoSQL
    operator injection or coercion bugs.

Type-juggling payloads are inspired by HackerOne reports against
Node.js / PHP / Python frameworks where `{"$ne": null}` or
`["array"]` reaches MongoDB / SQL builders unsanitized.
"""
import json
import logging

from app.scanner.plugins.base import Finding
from app.scanner.context import stable_fingerprint

logger = logging.getLogger("vulnscan.api_scanner.type_confusion")

_MAX_ENDPOINTS = 20
_MAX_PARAMS = 4

# Per-type set of intentionally wrong values
_WRONG_VALUES_BY_TYPE = {
    "integer": [
        ('["array"]', "array_for_int"),
        ('{"$ne":1}', "operator_object_for_int"),
        ('1e308', "float_overflow"),
        ('"abc"', "string_for_int"),
    ],
    "boolean": [
        ('"true"', "stringified_bool"),
        ('2', "out_of_range_bool"),
        ('null', "null_for_bool"),
        ('{"$ne":null}', "operator_object_for_bool"),
    ],
    "string": [
        ('["a","b"]', "array_for_string"),
        ('{"$gt":""}', "operator_object_for_string"),
        ('null', "null_for_string"),
        ('"' + "A" * 8000 + '"', "very_long_string"),
    ],
    "number": [
        ('["array"]', "array_for_number"),
        ('{"$ne":1}', "operator_object_for_number"),
        ('"NaN"', "string_for_number"),
    ],
}

_LEN_DIFF_RATIO = 0.30
_LEN_DIFF_MIN = 80


def _typed_default(p):
    if p.example is not None and p.example != "":
        return p.example
    if p.param_type == "integer" or p.param_type == "number":
        return 1
    if p.param_type == "boolean":
        return False
    return "test"


async def _send_with_param_value(client, ep, param, value_json):
    """Send the endpoint with a JSON-encoded raw value substituted for the param."""
    if param.location == "query":
        # Strip surrounding quotes if it was a JSON string so it goes
        # over the wire as expected by query encoding.
        value = value_json
        if value_json.startswith('"') and value_json.endswith('"'):
            try:
                value = json.loads(value_json)
            except Exception:
                value = value_json
        return await client.request(ep.method, ep.path, params={param.name: value})

    if param.location == "path":
        path = ep.path.replace(
            f"{{{param.name}}}",
            value_json.strip('"'),
        )
        return await client.request(ep.method, path)

    if param.location == "body":
        # Build body with this param replaced by the raw JSON value
        body = {}
        for p in ep.parameters:
            if p.location != "body":
                continue
            body[p.name] = _typed_default(p)
        try:
            body[param.name] = json.loads(value_json)
        except (json.JSONDecodeError, ValueError):
            body[param.name] = value_json
        return await client.send_raw(ep.method, ep.path, body=body)

    # header / cookie not supported here
    return None


async def check(client, endpoints, ctx) -> list[Finding]:
    findings = []
    target = ctx.get("target_raw", "unknown")
    seen_fps: set[str] = set()

    candidates = endpoints[:_MAX_ENDPOINTS]
    for ep in candidates:
        injectable = [p for p in ep.parameters
                      if p.location in ("query", "path", "body")
                      and p.param_type in _WRONG_VALUES_BY_TYPE]
        if not injectable:
            continue

        # Establish typed baseline for this endpoint
        try:
            baseline = await client.baseline_request(ep)
        except Exception:
            continue
        if baseline.status in (0, 404, 405):
            continue

        for param in injectable[:_MAX_PARAMS]:
            payloads = _WRONG_VALUES_BY_TYPE.get(param.param_type, [])
            for value_json, desc in payloads:
                try:
                    resp = await _send_with_param_value(client, ep, param, value_json)
                except Exception as e:
                    logger.debug("Type-confusion probe failed: %s", e)
                    continue
                if resp is None or resp.status == 0:
                    continue

                # Server crashed on wrong type → strong signal
                if 500 <= resp.status < 600:
                    fp = stable_fingerprint(target, "api.scanner.type_confusion",
                                            "5xx", ep.path, param.name, desc)
                    if fp in seen_fps:
                        continue
                    seen_fps.add(fp)
                    findings.append(Finding(
                        severity="medium",
                        plugin_id="api.scanner.type_confusion",
                        title=f"Type confusion 5xx: {ep.method} {ep.path} [{param.name}]",
                        description=(
                            f"Submitting a wrong-type value ({desc}) for "
                            f"'{param.name}' (declared {param.param_type}) "
                            f"caused a {resp.status} server error. The framework "
                            "did not validate or safely coerce the input — wrong "
                            "types reach application code, which is the precursor "
                            "to NoSQL operator injection and coercion bugs."
                        ),
                        evidence=(
                            f"path={ep.path} method={ep.method} param={param.name} "
                            f"declared_type={param.param_type} payload={desc} "
                            f"value={value_json[:80]} status={resp.status}"
                        ),
                        affected=target,
                        fingerprint=fp,
                        confidence=0.8,
                        cvss=5.3,
                        remediation=(
                            "[MEDIUM] Validate request types at the boundary "
                            "(pydantic / JSON schema / class-validator). Reject "
                            "wrong-type values with 400 instead of letting them "
                            "reach handlers. For NoSQL backends, also reject "
                            "object-shaped values in string fields."
                        ),
                        references=[
                            "https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/",
                            "https://owasp.org/www-community/attacks/NoSQL_Injection",
                        ],
                    ))
                    break

                # Substantively different 200 body
                if resp.status == 200 and baseline.status == 200 and baseline.body_length > 0:
                    diff = abs(resp.body_length - baseline.body_length)
                    ratio = diff / max(baseline.body_length, 1)
                    if diff >= _LEN_DIFF_MIN and ratio >= _LEN_DIFF_RATIO:
                        fp = stable_fingerprint(target, "api.scanner.type_confusion",
                                                "divergent", ep.path, param.name, desc)
                        if fp in seen_fps:
                            continue
                        seen_fps.add(fp)
                        findings.append(Finding(
                            severity="low",
                            plugin_id="api.scanner.type_confusion",
                            title=f"Wrong-type accepted with divergent response: {ep.path} [{param.name}]",
                            description=(
                                f"Wrong-type payload ({desc}) for '{param.name}' "
                                f"returned 200 with a body length differing "
                                f"{ratio*100:.0f}% from the typed baseline. The "
                                "server accepts and acts on inputs that violate "
                                "the declared schema."
                            ),
                            evidence=(
                                f"path={ep.path} param={param.name} payload={desc} "
                                f"baseline_len={baseline.body_length} "
                                f"injected_len={resp.body_length} ratio={ratio:.2f}"
                            ),
                            affected=target,
                            fingerprint=fp,
                            confidence=0.55,
                            cvss=3.7,
                            remediation=(
                                "[LOW] Enforce request-side type validation. "
                                "Inputs violating the declared schema should be "
                                "rejected with 400."
                            ),
                        ))
                        break

    return findings
