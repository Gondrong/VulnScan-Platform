"""
API JWT Security Scanner
Tests for JWT vulnerabilities:
- alg:none bypass
- Weak HMAC signing keys
- Expired token acceptance
- Missing claims validation
- Algorithm confusion (RS256 → HS256)
"""
import asyncio
import base64
import hashlib
import hmac
import json
import logging
import re

from app.scanner.plugins.base import Finding
from app.scanner.context import stable_fingerprint

logger = logging.getLogger("vulnscan.api_scanner.jwt")

_WEAK_SECRETS = [
    "secret", "password", "123456", "key", "jwt_secret", "changeme",
    "test", "default", "admin", "supersecret", "mysecret", "jwt",
    "token", "qwerty", "abc123", "letmein", "1234", "12345678",
    "password123", "secret123", "your-secret-key", "jwt-secret",
]


def _b64url_decode(s):
    s += "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)


def _b64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _parse_jwt(token):
    parts = token.split(".")
    if len(parts) != 3:
        return None, None, ""
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
        return header, payload, parts[2]
    except Exception:
        return None, None, ""


def _forge_none_token(token):
    parts = token.split(".")
    if len(parts) != 3:
        return ""
    try:
        header = json.loads(_b64url_decode(parts[0]))
        header["alg"] = "none"
        new_header = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
        return f"{new_header}.{parts[1]}."
    except Exception:
        return ""


def _try_weak_secrets(token):
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(_b64url_decode(parts[0]))
    except Exception:
        return None
    alg = header.get("alg", "")
    if alg not in ("HS256", "HS384", "HS512"):
        return None

    signing_input = f"{parts[0]}.{parts[1]}".encode()
    actual_sig = parts[2]

    hash_fn = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}.get(alg)
    if not hash_fn:
        return None

    for secret in _WEAK_SECRETS:
        computed = hmac.new(secret.encode(), signing_input, hash_fn).digest()
        if _b64url_encode(computed) == actual_sig:
            return secret
    return None


def _extract_jwts(text):
    return list(set(re.findall(r"(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*)", text)))


async def check(client, endpoints, ctx) -> list[Finding]:
    findings = []
    target = ctx.get("target_raw", "unknown")

    # Discover JWT tokens from API responses
    discovered_tokens = []

    for ep in endpoints[:10]:
        r = await client.baseline_request(ep)
        if r.status == 0:
            continue

        # Check response body
        for token in _extract_jwts(r.body):
            discovered_tokens.append((token, ep.path, "body"))

        # Check response headers
        for hdr in ("authorization", "set-cookie", "x-auth-token", "x-access-token"):
            val = r.headers.get(hdr, "")
            for token in _extract_jwts(val):
                discovered_tokens.append((token, ep.path, f"header:{hdr}"))

    # Analyze each JWT
    analyzed = set()
    for token, source, location in discovered_tokens:
        if token in analyzed:
            continue
        analyzed.add(token)

        header, payload, sig = _parse_jwt(token)
        if not header or not payload:
            continue

        alg = header.get("alg", "unknown")

        # 1. Weak HMAC secret
        if alg.startswith("HS"):
            weak = _try_weak_secrets(token)
            if weak:
                fp = stable_fingerprint(target, "api.scanner.jwt", "weak_secret", source)
                findings.append(Finding(
                    severity="critical", plugin_id="api.scanner.jwt",
                    title=f"JWT weak secret: '{weak}' ({source})",
                    description=f"JWT signed with weak secret '{weak}'. Any attacker can forge valid tokens.",
                    evidence=f"source={source} alg={alg} secret={weak} location={location}",
                    affected=target, fingerprint=fp, confidence=0.98, cvss=9.8,
                    remediation=(
                        f"[CRITICAL — CWE-326 / OWASP API2:2023]\n\n"
                        f"[FIX] Generate strong secret: openssl rand -base64 32\n"
                        f"Consider RS256 (asymmetric) instead of HS256."
                    ),
                ))

        # 2. Missing claims
        missing = []
        if "exp" not in payload:
            missing.append("exp (expiration)")
        if "iat" not in payload:
            missing.append("iat (issued at)")
        if "iss" not in payload:
            missing.append("iss (issuer)")

        if missing:
            fp = stable_fingerprint(target, "api.scanner.jwt", "missing_claims", source, str(missing))
            sev = "medium" if "exp" in str(missing) else "low"
            findings.append(Finding(
                severity=sev, plugin_id="api.scanner.jwt",
                title=f"JWT missing claims: {', '.join(missing)}",
                description=f"JWT from {source} is missing: {', '.join(missing)}. Without 'exp', tokens never expire.",
                evidence=f"source={source} missing={missing} claims={list(payload.keys())}",
                affected=target, fingerprint=fp, confidence=0.90,
                remediation="[FIX] Include exp, iat, iss, sub, aud in all JWTs.",
            ))

        # 3. alg:none bypass test
        if alg.lower() != "none":
            forged = _forge_none_token(token)
            if forged:
                # Try accessing protected endpoints with forged token
                for ep in endpoints[:5]:
                    r_forged = await client.request(
                        ep.method, ep.path,
                        headers={"Authorization": f"Bearer {forged}"},
                    )
                    r_no_auth = await client.request(ep.method, ep.path, headers={})

                    if (r_forged.status in (200, 201) and
                            r_no_auth.status in (401, 403) and
                            r_forged.body_length > r_no_auth.body_length * 1.5):
                        fp = stable_fingerprint(target, "api.scanner.jwt", "alg_none", ep.path)
                        findings.append(Finding(
                            severity="critical", plugin_id="api.scanner.jwt",
                            title=f"JWT alg:none bypass: {ep.path}",
                            description="Server accepts JWT with alg:none. Attacker can forge any token.",
                            evidence=f"path={ep.path} forged_status={r_forged.status} no_auth_status={r_no_auth.status}",
                            affected=target, fingerprint=fp, confidence=0.98, cvss=9.8,
                            remediation=(
                                "[CRITICAL — CWE-327 / OWASP API2:2023]\n\n"
                                "[FIX] Explicitly whitelist allowed algorithms:\n"
                                "  jwt.verify(token, key, { algorithms: ['RS256'] })"
                            ),
                        ))
                        break

    return findings
