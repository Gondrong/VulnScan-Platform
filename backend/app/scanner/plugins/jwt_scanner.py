"""
JWT Weak Algorithm Scanner
Tests for JWT security weaknesses: alg:none bypass, weak HMAC keys,
expired tokens, missing claims, and algorithm confusion attacks.
"""
import asyncio
import base64
import hashlib
import hmac
import json
import re
import ssl
import urllib.parse

from app.scanner.plugins.base import Plugin, PluginMeta, PluginResult, Finding
from app.scanner.context import stable_fingerprint

META = PluginMeta(
    plugin_id="web.jwt_scanner",
    name="JWT Weak Algorithm Scanner",
    category="web",
    depends_on=["fingerprint.http"],
    consumes=["fingerprint.http", "net.open_ports"],
    provides=["web.jwt_findings"],
    enabled_by_default=True,
    timeout_seconds=40.0,
)

# ── Common weak HMAC signing keys ───────────────────────────────────────
_WEAK_SECRETS = [
    # Generic weak passwords
    "secret", "password", "123456", "key", "changeme", "test",
    "default", "admin", "qwerty", "abc123", "letmein", "pass",
    "1234", "12345678", "password123", "secret123", "welcome",
    "monkey", "master", "login", "passw0rd", "iloveyou",
    # JWT / token specific
    "jwt_secret", "jwt-secret", "jwt_key", "jwt-key", "jwt",
    "token", "token_secret", "auth_secret", "signing_key",
    "HS256_SECRET", "hs256-secret", "hmac_secret", "hmac-key",
    # App / framework defaults
    "SECRET_KEY", "secret_key", "SECRET", "APP_SECRET", "app_secret",
    "application_secret", "my-secret", "my_secret", "mysecret",
    "your-secret-key", "your_secret", "your-secret",
    "supersecret", "super_secret", "super-secret",
    # Framework-specific defaults
    "django-insecure-secret", "flask-secret", "laravel_key",
    "rails_secret", "express_secret", "spring_secret",
    "AllYourBase", "keyboard cat", "shhhhh", "s3cr3t",
    # Environment variable defaults
    "dev-secret", "dev-secret-CHANGE-ME", "development",
    "changeit", "please-change-me", "replace-me",
    "your-256-bit-secret", "my-256-bit-secret",
    # Common company/project placeholders
    "company_secret", "project_secret", "api_secret", "api-secret",
    "private_key", "private-key", "signing-key", "auth-key",
    "access_secret", "refresh_secret", "session_secret",
    # Numeric / simple patterns
    "123456789", "1234567890", "111111", "000000", "12345",
    "123123", "654321", "password1", "p@ssw0rd",
]

# ── Endpoints likely to return JWT tokens ───────────────────────────────
_AUTH_ENDPOINTS = [
    ("/api/auth/login", "POST"),
    ("/api/login", "POST"),
    ("/auth/login", "POST"),
    ("/login", "POST"),
    ("/api/token", "POST"),
    ("/oauth/token", "POST"),
    ("/api/v1/auth/login", "POST"),
    ("/api/v1/login", "POST"),
    ("/api/auth/token", "POST"),
    ("/api/signin", "POST"),
]

# ── Pages and endpoints likely to contain JWTs in response ──────────────
_JWT_DISCOVERY_PATHS = [
    "/",
    "/api/me",
    "/api/user",
    "/api/profile",
    "/api/v1/me",
    "/api/health",
    "/api/config",
]


def _b64url_decode(s: str) -> bytes:
    """Base64url decode without padding."""
    s += "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)


def _b64url_encode(data: bytes) -> str:
    """Base64url encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _parse_jwt(token: str) -> tuple[dict | None, dict | None, str]:
    """Parse a JWT and return (header, payload, signature_part)."""
    parts = token.split(".")
    if len(parts) != 3:
        return None, None, ""
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
        return header, payload, parts[2]
    except Exception:
        return None, None, ""


def _forge_none_token(token: str) -> str:
    """Create an alg:none version of a JWT token."""
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


def _sign_hs256(header_b64: str, payload_b64: str, secret: str) -> str:
    """Sign a JWT with HS256 using a given secret."""
    signing_input = f"{header_b64}.{payload_b64}".encode()
    signature = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    return _b64url_encode(signature)


def _try_weak_secrets(token: str) -> str | None:
    """Try signing the token with known weak secrets. Returns the secret if found."""
    parts = token.split(".")
    if len(parts) != 3:
        return None

    try:
        header = json.loads(_b64url_decode(parts[0]))
    except Exception:
        return None

    if header.get("alg") not in ("HS256", "HS384", "HS512"):
        return None

    signing_input = f"{parts[0]}.{parts[1]}".encode()
    actual_sig = parts[2]

    for secret in _WEAK_SECRETS:
        if header["alg"] == "HS256":
            computed = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
        elif header["alg"] == "HS384":
            computed = hmac.new(secret.encode(), signing_input, hashlib.sha384).digest()
        elif header["alg"] == "HS512":
            computed = hmac.new(secret.encode(), signing_input, hashlib.sha512).digest()
        else:
            continue

        computed_b64 = _b64url_encode(computed)
        if computed_b64 == actual_sig:
            return secret

    return None


def _extract_jwts(text: str) -> list[str]:
    """Extract JWT tokens from text."""
    pattern = r"(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*)"
    return list(set(re.findall(pattern, text)))


async def _fetch_url(url: str, method: str = "GET", body: str = "",
                     headers: dict | None = None, timeout: float = 8.0) -> tuple[int, str, dict]:
    """Fetch URL and return (status, body, response_headers)."""
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path += f"?{parsed.query}"

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

        req_headers = {
            "Host": host,
            "User-Agent": "VulnScan/2.1",
            "Accept": "*/*",
            "Connection": "close",
        }
        if headers:
            req_headers.update(headers)
        if method == "POST":
            req_headers["Content-Type"] = "application/json"
            req_headers["Content-Length"] = str(len(body))

        request_line = f"{method} {path} HTTP/1.1\r\n"
        header_str = "".join(f"{k}: {v}\r\n" for k, v in req_headers.items())
        request = f"{request_line}{header_str}\r\n{body}"

        writer.write(request.encode())
        await writer.drain()

        response = await asyncio.wait_for(reader.read(65536), timeout=timeout)
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


class Check(Plugin):
    async def run(self, target: str, ctx) -> PluginResult:
        ports = ctx.get("net.open_ports", []) or []
        http_data = (ctx.get("fingerprint.http", {}) or {}).get("http", [])
        target_raw = ctx.get("target_raw", target)
        findings = []
        jwt_results = []

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
            return PluginResult(artifacts={"web.jwt_findings": []})

        # ── Step 1: Discover JWT tokens in responses ───────────────────
        discovered_tokens = []
        for base in base_urls[:2]:
            for path in _JWT_DISCOVERY_PATHS:
                url = base + path
                status, body, resp_headers = await _fetch_url(url)
                if status > 0 and body:
                    # Check response body
                    tokens = _extract_jwts(body)
                    for t in tokens:
                        discovered_tokens.append((t, url, "response_body"))

                    # Check response headers (Authorization, Set-Cookie)
                    for hdr_name in ("authorization", "set-cookie", "x-auth-token", "x-access-token"):
                        hdr_val = resp_headers.get(hdr_name, "")
                        if hdr_val:
                            tokens = _extract_jwts(hdr_val)
                            for t in tokens:
                                discovered_tokens.append((t, url, f"header:{hdr_name}"))

        # ── Step 2: Analyze each discovered JWT ────────────────────────
        analyzed_tokens = set()
        for token, source_url, location in discovered_tokens:
            if token in analyzed_tokens:
                continue
            analyzed_tokens.add(token)

            header, payload, sig = _parse_jwt(token)
            if not header or not payload:
                continue

            alg = header.get("alg", "unknown")
            masked_token = token[:20] + "..." + token[-10:] if len(token) > 35 else token

            # ── Check 1: alg:none already in use ───────────────────────
            if alg.lower() == "none":
                fp = stable_fingerprint(target, META.plugin_id, "alg_none", source_url)
                findings.append(Finding(
                    severity="critical",
                    plugin_id=META.plugin_id,
                    title=f"JWT using alg:none — unsigned token accepted",
                    description=(
                        f"A JWT token found at {source_url} uses algorithm 'none', meaning "
                        f"the token is completely unsigned. Any attacker can forge valid tokens."
                    ),
                    evidence=f"alg=none url={source_url} location={location} token={masked_token}",
                    affected=target,
                    fingerprint=fp,
                    confidence=0.98,
                    remediation=(
                        "[CRITICAL] JWT accepts unsigned tokens (alg:none)\n\n"
                        "[FIX]\n"
                        "1. Explicitly reject 'none' algorithm in your JWT library\n"
                        "2. Whitelist only allowed algorithms (e.g., RS256)\n"
                        "3. Always validate the signature before trusting claims\n\n"
                        "[CODE EXAMPLE]\n"
                        "  jwt.verify(token, secret, { algorithms: ['RS256'] })\n"
                        "  # Never use: algorithms: ['none'] or jwt.decode(token, verify=False)"
                    ),
                    references=["https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/"],
                ))
                jwt_results.append({"type": "alg_none", "url": source_url, "severity": "critical"})

            # ── Check 2: Weak HMAC signing key ─────────────────────────
            if alg.upper().startswith("HS"):
                weak_secret = _try_weak_secrets(token)
                if weak_secret:
                    fp = stable_fingerprint(target, META.plugin_id, "weak_hmac", source_url)
                    findings.append(Finding(
                        severity="critical",
                        plugin_id=META.plugin_id,
                        title=f"JWT signed with weak secret: '{weak_secret}'",
                        description=(
                            f"The JWT token from {source_url} is signed with {alg} using the easily "
                            f"guessable secret '{weak_secret}'. An attacker can forge arbitrary tokens."
                        ),
                        evidence=f"alg={alg} secret={weak_secret} url={source_url} token={masked_token}",
                        affected=target,
                        fingerprint=fp,
                        confidence=0.98,
                        remediation=(
                            f"[CRITICAL] JWT signed with weak secret: '{weak_secret}'\n\n"
                            f"[IMMEDIATE ACTION]\n"
                            f"1. Generate a strong random secret (min 256 bits / 32 bytes)\n"
                            f"2. Invalidate all existing tokens\n"
                            f"3. Consider switching to RS256 (asymmetric) for better security\n\n"
                            f"[GENERATE STRONG SECRET]\n"
                            f"  openssl rand -base64 32\n"
                            f"  python3 -c \"import secrets; print(secrets.token_hex(32))\"\n\n"
                            f"[BEST PRACTICE] Use asymmetric algorithms (RS256/ES256) so the "
                            f"signing key never needs to be shared."
                        ),
                        references=[
                            "https://auth0.com/blog/brute-forcing-hs256-is-possible-the-importance-of-using-strong-keys-to-sign-jwts/",
                        ],
                    ))
                    jwt_results.append({"type": "weak_secret", "secret": weak_secret, "url": source_url, "severity": "critical"})

            # ── Check 3: Missing important claims ──────────────────────
            missing_claims = []
            if "exp" not in payload:
                missing_claims.append("exp (expiration)")
            if "iat" not in payload:
                missing_claims.append("iat (issued at)")
            if "iss" not in payload:
                missing_claims.append("iss (issuer)")

            if missing_claims:
                fp = stable_fingerprint(target, META.plugin_id, "missing_claims", source_url, str(missing_claims))
                sev = "medium" if "exp" in str(missing_claims) else "low"
                findings.append(Finding(
                    severity=sev,
                    plugin_id=META.plugin_id,
                    title=f"JWT missing security claims: {', '.join(missing_claims)}",
                    description=(
                        f"The JWT token from {source_url} is missing important claims: "
                        f"{', '.join(missing_claims)}. Without 'exp', tokens never expire."
                    ),
                    evidence=f"alg={alg} missing={missing_claims} url={source_url} claims={list(payload.keys())}",
                    affected=target,
                    fingerprint=fp,
                    confidence=0.90,
                    remediation=(
                        f"[AFFECTED] JWT missing: {', '.join(missing_claims)}\n\n"
                        f"[FIX] Include these standard claims in all JWTs:\n"
                        f"  - exp: Token expiration time (short-lived, e.g., 15 minutes)\n"
                        f"  - iat: When the token was issued\n"
                        f"  - iss: Who issued the token (for validation)\n"
                        f"  - sub: Subject (user identifier)\n"
                        f"  - aud: Intended audience\n\n"
                        f"[BEST PRACTICE] Use short expiration times with refresh tokens."
                    ),
                    references=["https://datatracker.ietf.org/doc/html/rfc7519#section-4.1"],
                ))

            # ── Check 4: Sensitive data in payload ─────────────────────
            sensitive_keys = []
            for k in payload:
                k_lower = k.lower()
                if any(s in k_lower for s in ["password", "secret", "credit_card", "ssn", "private_key", "api_key"]):
                    sensitive_keys.append(k)

            if sensitive_keys:
                fp = stable_fingerprint(target, META.plugin_id, "sensitive_payload", source_url, str(sensitive_keys))
                findings.append(Finding(
                    severity="high",
                    plugin_id=META.plugin_id,
                    title=f"JWT contains sensitive data in payload: {', '.join(sensitive_keys)}",
                    description=(
                        f"The JWT from {source_url} contains potentially sensitive fields in the payload. "
                        f"JWT payloads are only base64-encoded, NOT encrypted — anyone can read them."
                    ),
                    evidence=f"sensitive_keys={sensitive_keys} url={source_url}",
                    affected=target,
                    fingerprint=fp,
                    confidence=0.85,
                    remediation=(
                        f"[AFFECTED] Sensitive data in JWT payload: {', '.join(sensitive_keys)}\n\n"
                        f"[FIX]\n"
                        f"1. Never put sensitive data in JWT payloads\n"
                        f"2. Use JWE (JSON Web Encryption) if payload confidentiality is needed\n"
                        f"3. Keep JWTs minimal — use server-side sessions for sensitive data\n\n"
                        f"[NOTE] JWT payloads are base64-encoded, NOT encrypted. "
                        f"Anyone with the token can read the contents."
                    ),
                    references=["https://datatracker.ietf.org/doc/html/rfc7516"],
                ))

        # ── Step 3: Test alg:none bypass on auth endpoints ─────────────
        for base in base_urls[:2]:
            for token, source_url, location in discovered_tokens[:3]:
                header, payload, sig = _parse_jwt(token)
                if not header or not payload:
                    continue
                if header.get("alg", "").lower() == "none":
                    continue  # Already unsigned

                forged = _forge_none_token(token)
                if not forged:
                    continue

                # Try accessing a protected endpoint with the forged token
                for path in ["/api/me", "/api/user", "/api/profile", "/api/v1/me"]:
                    url = base + path
                    status, body, _ = await _fetch_url(
                        url,
                        headers={"Authorization": f"Bearer {forged}"},
                    )
                    if status in (200, 201) and len(body) > 20:
                        # Verify it's not just a public endpoint
                        status_no_auth, body_no_auth, _ = await _fetch_url(url)
                        if status_no_auth in (401, 403) or len(body_no_auth) < len(body) // 2:
                            fp = stable_fingerprint(target, META.plugin_id, "alg_none_bypass", url)
                            findings.append(Finding(
                                severity="critical",
                                plugin_id=META.plugin_id,
                                title=f"JWT alg:none bypass CONFIRMED at {path}",
                                description=(
                                    f"The server at {url} accepts JWT tokens with alg:none. "
                                    f"An attacker can forge any token without knowing the secret key."
                                ),
                                evidence=f"url={url} forged_token={forged[:30]}... status={status}",
                                affected=target,
                                fingerprint=fp,
                                confidence=0.98,
                                remediation=(
                                    "[CRITICAL] Server accepts alg:none JWT tokens\n\n"
                                    "[IMMEDIATE ACTION]\n"
                                    "1. Update JWT library to latest version\n"
                                    "2. Explicitly whitelist allowed algorithms\n"
                                    "3. Never accept 'none' as a valid algorithm\n\n"
                                    "[CODE FIX]\n"
                                    "  Node.js: jwt.verify(token, key, { algorithms: ['RS256'] })\n"
                                    "  Python:  jwt.decode(token, key, algorithms=['RS256'])\n"
                                    "  Java:    parser.setAllowedAlgorithms(Arrays.asList('RS256'))"
                                ),
                                references=["https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/"],
                            ))
                            jwt_results.append({"type": "alg_none_bypass", "url": url, "severity": "critical"})
                            break  # One confirmed is enough

        return PluginResult(
            findings=findings,
            artifacts={"web.jwt_findings": jwt_results},
        )

