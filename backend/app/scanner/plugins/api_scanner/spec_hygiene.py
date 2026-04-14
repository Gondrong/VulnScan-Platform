"""
API Spec Hygiene — passive analysis of the supplied OpenAPI / Swagger /
Postman document. No HTTP requests are issued.

Findings:
  • Endpoints declared without any auth scheme
  • No securitySchemes / global security defined at all
  • Wildcard CORS configured in the spec (`*`)
  • Real-looking secrets embedded as `example` values (sk_live_, AKIA, etc.)
  • Plain HTTP server entries (no TLS)

This complements the active checks: spec hygiene catches mistakes
before any traffic is sent, and is the cheapest source of high-signal
findings when the spec is well-maintained.
"""
import json
import logging
import re

from app.scanner.plugins.base import Finding
from app.scanner.context import stable_fingerprint

logger = logging.getLogger("vulnscan.api_scanner.spec_hygiene")

_SECRET_PATTERNS = [
    (re.compile(r"sk_live_[A-Za-z0-9]{16,}"), "Stripe live secret key"),
    (re.compile(r"sk_test_[A-Za-z0-9]{16,}"), "Stripe test secret key"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS access key id"),
    (re.compile(r"AIza[0-9A-Za-z\-_]{35}"), "Google API key"),
    (re.compile(r"ghp_[A-Za-z0-9]{30,}"), "GitHub personal access token"),
    (re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"), "Slack token"),
    (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), "private key"),
    (re.compile(r"eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
     "JWT-shaped value"),
]

_GENERIC_HINTS = re.compile(r"\b(password|passwd|secret|token|api[_-]?key)\b", re.I)


def _walk_for_examples(node, path="$"):
    """Yield (json_path, key, value) for every string-valued example in spec."""
    if isinstance(node, dict):
        for k, v in node.items():
            new_path = f"{path}.{k}"
            if k in ("example", "default", "x-example") and isinstance(v, str):
                yield (new_path, k, v)
            if isinstance(v, (dict, list)):
                yield from _walk_for_examples(v, new_path)
    elif isinstance(node, list):
        for i, v in enumerate(node[:50]):
            if isinstance(v, (dict, list)):
                yield from _walk_for_examples(v, f"{path}[{i}]")


def _load_spec_dict(raw):
    """Coerce the raw spec into a dict for inspection (best-effort)."""
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, (bytes, bytearray)):
        try:
            raw = raw.decode("utf-8", errors="ignore")
        except Exception:
            return None
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            try:
                import yaml  # noqa: WPS433
                return yaml.safe_load(raw)
            except Exception:
                return None
    return None


async def check(client, endpoints, ctx) -> list[Finding]:
    findings = []
    target = ctx.get("target_raw", "unknown")
    raw_spec = ctx.get("api.spec_raw")
    spec = _load_spec_dict(raw_spec)

    # 1) Endpoints declared without auth_schemes
    no_auth_eps = [ep for ep in endpoints if not ep.auth_schemes]
    if no_auth_eps and len(no_auth_eps) >= max(1, int(len(endpoints) * 0.2)):
        examples = [f"{ep.method} {ep.path}" for ep in no_auth_eps[:8]]
        fp = stable_fingerprint(target, "api.scanner.spec_hygiene", "no_auth_endpoints")
        findings.append(Finding(
            severity="medium",
            plugin_id="api.scanner.spec_hygiene",
            title=f"{len(no_auth_eps)}/{len(endpoints)} endpoints declared without auth",
            description=(
                "The supplied spec lists endpoints with no security requirement. "
                "Either the endpoints are intentionally public (and should be "
                "labelled in the spec to make that explicit) or the spec is "
                "missing required `security` declarations."
            ),
            evidence=f"unauth_endpoints={len(no_auth_eps)} examples={examples}",
            affected=target,
            fingerprint=fp,
            confidence=1.0,
            cvss=4.3,
            remediation=(
                "[MEDIUM] Apply a global `security` requirement at the spec root "
                "and explicitly opt out (`security: []`) for endpoints that are "
                "truly public. Avoid the implicit-no-auth pattern."
            ),
            references=[
                "https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/",
            ],
        ))

    # 2) Spec dict-level checks (need the parsed dict)
    if spec:
        # 2a) No securitySchemes at all
        oa3_schemes = (spec.get("components") or {}).get("securitySchemes")
        sw2_schemes = spec.get("securityDefinitions")
        if not oa3_schemes and not sw2_schemes:
            fp = stable_fingerprint(target, "api.scanner.spec_hygiene",
                                    "no_security_schemes")
            findings.append(Finding(
                severity="info",
                plugin_id="api.scanner.spec_hygiene",
                title="Spec defines no securitySchemes",
                description=(
                    "The spec contains no `components.securitySchemes` (OpenAPI 3) "
                    "or `securityDefinitions` (Swagger 2) section. Tooling cannot "
                    "reason about authentication for this API."
                ),
                evidence="components.securitySchemes=None",
                affected=target,
                fingerprint=fp,
                confidence=1.0,
                remediation=(
                    "[INFO] Document the authentication scheme(s) the API uses "
                    "in `components.securitySchemes`."
                ),
            ))

        # 2b) Wildcard CORS in spec extensions / x-cors / responses
        spec_str = json.dumps(spec, default=str)
        if re.search(r'"Access-Control-Allow-Origin"\s*:\s*[^,}]*\*', spec_str):
            fp = stable_fingerprint(target, "api.scanner.spec_hygiene", "wildcard_cors")
            findings.append(Finding(
                severity="medium",
                plugin_id="api.scanner.spec_hygiene",
                title="Wildcard CORS declared in spec",
                description=(
                    "The spec advertises Access-Control-Allow-Origin: *. With "
                    "credentialed APIs this is rejected by browsers; with "
                    "uncredentialed but sensitive APIs it broadens reach for "
                    "cross-site attacks."
                ),
                evidence='Access-Control-Allow-Origin: *',
                affected=target,
                fingerprint=fp,
                confidence=0.9,
                cvss=5.3,
                remediation=(
                    "[MEDIUM] Replace `*` with an explicit allow-list of trusted "
                    "origins. Never combine wildcard origin with "
                    "Access-Control-Allow-Credentials: true."
                ),
            ))

        # 2c) Plain HTTP servers
        servers = spec.get("servers") or []
        if isinstance(servers, list):
            http_only = [s.get("url", "") for s in servers
                         if isinstance(s, dict)
                         and isinstance(s.get("url", ""), str)
                         and s.get("url", "").startswith("http://")]
            if http_only:
                fp = stable_fingerprint(target, "api.scanner.spec_hygiene", "plain_http")
                findings.append(Finding(
                    severity="low",
                    plugin_id="api.scanner.spec_hygiene",
                    title=f"{len(http_only)} server URL(s) use plain HTTP",
                    description=(
                        "The spec lists server URLs that are not HTTPS. Sensitive "
                        "API traffic must be transport-encrypted."
                    ),
                    evidence=f"http_servers={http_only[:5]}",
                    affected=target,
                    fingerprint=fp,
                    confidence=1.0,
                    cvss=3.1,
                    remediation="[LOW] Serve the API only over HTTPS.",
                ))

        # 2d) Real secrets in example values
        secret_hits = []
        generic_hits = []
        for jpath, key, value in _walk_for_examples(spec):
            for pat, label in _SECRET_PATTERNS:
                if pat.search(value):
                    secret_hits.append((jpath, label, value[:30]))
                    break
            else:
                if _GENERIC_HINTS.search(jpath) and value and len(value) >= 8:
                    generic_hits.append((jpath, value[:30]))

        if secret_hits:
            samples = ", ".join(f"{p}={lbl}({v}...)"
                                for p, lbl, v in secret_hits[:5])
            fp = stable_fingerprint(target, "api.scanner.spec_hygiene",
                                    "secret_in_example")
            findings.append(Finding(
                severity="high",
                plugin_id="api.scanner.spec_hygiene",
                title=f"Real-looking secrets in spec examples ({len(secret_hits)})",
                description=(
                    "One or more `example` values in the spec match patterns for "
                    "real secrets (AWS keys, Stripe keys, JWTs, private keys, "
                    "etc.). These leak into generated docs, SDKs and version "
                    "control."
                ),
                evidence=f"hits={len(secret_hits)} samples={samples}",
                affected=target,
                fingerprint=fp,
                confidence=0.95,
                cvss=7.5,
                remediation=(
                    "[HIGH] Replace example values with obvious placeholders "
                    "(`<your-key-here>`). Rotate any keys that were committed."
                ),
                references=[
                    "https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/",
                ],
            ))
        elif generic_hits:
            samples = ", ".join(f"{p}={v}" for p, v in generic_hits[:5])
            fp = stable_fingerprint(target, "api.scanner.spec_hygiene",
                                    "credential_named_example")
            findings.append(Finding(
                severity="low",
                plugin_id="api.scanner.spec_hygiene",
                title=f"Examples named like credentials ({len(generic_hits)})",
                description=(
                    "Spec contains `example` values under fields named like "
                    "credentials (password/secret/token/api_key). Examples often "
                    "end up in published docs."
                ),
                evidence=f"hits={len(generic_hits)} samples={samples}",
                affected=target,
                fingerprint=fp,
                confidence=0.7,
                cvss=3.1,
                remediation=(
                    "[LOW] Use placeholders for credential examples; never check "
                    "real values into specs."
                ),
            ))

    return findings
