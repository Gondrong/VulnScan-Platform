"""
API Key / Token Exposure Scanner
Detects leaked API keys, tokens, and secrets in HTTP responses, JS bundles,
HTML source, and common API endpoints.
"""
import asyncio
import re
import math
import ssl
import urllib.parse

from app.scanner.plugins.base import Plugin, PluginMeta, PluginResult, Finding
from app.scanner.context import stable_fingerprint

META = PluginMeta(
    plugin_id="web.api_key_exposure",
    name="API Key & Token Exposure",
    category="web",
    depends_on=["fingerprint.http"],
    consumes=["fingerprint.http", "net.open_ports"],
    provides=["web.api_keys"],
    enabled_by_default=True,
    timeout_seconds=45.0,
)

# ── Known API key patterns ──────────────────────────────────────────────
# Each tuple: (name, regex, severity, confidence, reference_url)
_KEY_PATTERNS = [
    # AWS
    ("AWS Access Key ID", r"(?<![A-Za-z0-9/+=])(AKIA[0-9A-Z]{16})(?![A-Za-z0-9/+=])", "critical", 0.95,
     "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html"),
    ("AWS Secret Access Key", r"""(?:aws_secret_access_key|secret_key|secretkey)\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})['"]?""", "critical", 0.85,
     "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html"),
    # GitHub
    ("GitHub Personal Access Token", r"(?<![A-Za-z0-9_])(ghp_[A-Za-z0-9]{36,})(?![A-Za-z0-9_])", "critical", 0.95,
     "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens"),
    ("GitHub OAuth Token", r"(?<![A-Za-z0-9_])(gho_[A-Za-z0-9]{36,})(?![A-Za-z0-9_])", "critical", 0.95,
     "https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps"),
    ("GitHub App Token", r"(?<![A-Za-z0-9_])(ghu_[A-Za-z0-9]{36,})(?![A-Za-z0-9_])", "high", 0.90,
     "https://docs.github.com/en/apps"),
    # Slack
    ("Slack Bot Token", r"(?<![A-Za-z0-9\-])(xoxb-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{24,})(?![A-Za-z0-9\-])", "critical", 0.95,
     "https://api.slack.com/authentication/token-types"),
    ("Slack User Token", r"(?<![A-Za-z0-9\-])(xoxp-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{24,})(?![A-Za-z0-9\-])", "critical", 0.95,
     "https://api.slack.com/authentication/token-types"),
    ("Slack Webhook", r"(https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+)", "high", 0.95,
     "https://api.slack.com/messaging/webhooks"),
    # Google
    ("Google API Key", r"(?<![A-Za-z0-9\-_])(AIza[0-9A-Za-z\-_]{35})(?![A-Za-z0-9\-_])", "high", 0.90,
     "https://cloud.google.com/docs/authentication/api-keys"),
    ("Google OAuth Client Secret", r"""(?:client_secret)\s*[:=]\s*['"]?([A-Za-z0-9\-_]{24,})['"]?""", "high", 0.70,
     "https://cloud.google.com/docs/authentication"),
    # Stripe
    ("Stripe Secret Key", r"(?<![A-Za-z0-9_])(sk_live_[A-Za-z0-9]{24,})(?![A-Za-z0-9_])", "critical", 0.98,
     "https://stripe.com/docs/keys"),
    ("Stripe Publishable Key", r"(?<![A-Za-z0-9_])(pk_live_[A-Za-z0-9]{24,})(?![A-Za-z0-9_])", "low", 0.95,
     "https://stripe.com/docs/keys"),
    # Twilio
    ("Twilio API Key", r"(?<![A-Za-z0-9])(SK[0-9a-f]{32})(?![A-Za-z0-9])", "high", 0.80,
     "https://www.twilio.com/docs/iam/keys/api-key"),
    # SendGrid
    ("SendGrid API Key", r"(?<![A-Za-z0-9\.])(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})(?![A-Za-z0-9\._\-])", "critical", 0.95,
     "https://docs.sendgrid.com/ui/account-and-settings/api-keys"),
    # Mailgun
    ("Mailgun API Key", r"(?<![A-Za-z0-9\-])(key-[0-9a-zA-Z]{32})(?![A-Za-z0-9\-])", "high", 0.85,
     "https://documentation.mailgun.com/en/latest/api-intro.html"),
    # Heroku
    ("Heroku API Key", r"""(?:heroku.*api[_-]?key|HEROKU_API_KEY)\s*[:=]\s*['"]?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['"]?""", "high", 0.85,
     "https://devcenter.heroku.com/articles/authentication"),
    # Firebase
    ("Firebase Database URL", r"(https://[a-z0-9\-]+\.firebaseio\.com)", "medium", 0.80,
     "https://firebase.google.com/docs/database/security"),
    # Private Keys
    ("RSA Private Key", r"(-----BEGIN RSA PRIVATE KEY-----)", "critical", 0.98,
     "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/"),
    ("EC Private Key", r"(-----BEGIN EC PRIVATE KEY-----)", "critical", 0.98,
     "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/"),
    ("Generic Private Key", r"(-----BEGIN PRIVATE KEY-----)", "critical", 0.98,
     "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/"),
    # JWT in URL or response (not cookie — cookies are expected)
    ("Hardcoded JWT", r"""(?:token|jwt|bearer|auth)\s*[:=]\s*['"]?(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+)['"]?""", "high", 0.80,
     "https://jwt.io/introduction"),
    # Generic high-entropy secrets in common variable names
    ("Hardcoded Secret/Password", r"""(?:password|passwd|secret|api_key|apikey|api_secret|access_token|auth_token|private_key)\s*[:=]\s*['"]([A-Za-z0-9!@#$%^&*()_+\-=]{16,64})['"]""", "high", 0.65,
     "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/"),
]

# ── Paths to check for exposed secrets ──────────────────────────────────
_SENSITIVE_ENDPOINTS = [
    "/.env",
    "/.env.local",
    "/.env.production",
    "/.env.development",
    "/config.json",
    "/config.js",
    "/settings.json",
    "/api/config",
    "/api/settings",
    "/api/debug",
    "/api/info",
    "/debug/vars",
    "/actuator/env",
    "/actuator/configprops",
    "/__webpack_hmr",
    "/static/js/main.js",
    "/static/js/app.js",
    "/assets/js/app.js",
    "/bundle.js",
    "/app.js",
]


def _shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def _is_likely_real_key(value: str, name: str) -> bool:
    """
    Validate that a matched string is likely a real key, not a placeholder.
    Reduces false positives from example code, documentation, and templates.
    """
    lower = value.lower()

    # Reject obvious placeholders
    placeholders = [
        "xxxx", "yyyy", "example", "placeholder", "your_",
        "insert", "change_me", "todo", "fixme", "replace",
        "test_", "demo_", "sample", "dummy", "fake",
        "0000000", "1111111", "abcdef", "123456",
    ]
    if any(p in lower for p in placeholders):
        return False

    # Reject if it's all the same character
    if len(set(value)) < 4:
        return False

    # For generic secrets (not known-format keys), check entropy
    if name == "Hardcoded Secret/Password":
        entropy = _shannon_entropy(value)
        if entropy < 3.0:
            return False

    return True


async def _fetch_url(url: str, timeout: float = 8.0) -> tuple[int, str, dict]:
    """Fetch URL and return (status, body, headers)."""
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

        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: VulnScan/2.1\r\n"
            f"Accept: */*\r\n"
            f"Connection: close\r\n\r\n"
        )
        writer.write(request.encode())
        await writer.drain()

        response = await asyncio.wait_for(reader.read(65536), timeout=timeout)
        writer.close()

        text = response.decode("utf-8", errors="ignore")
        parts = text.split("\r\n\r\n", 1)
        header_block = parts[0] if parts else ""
        body = parts[1] if len(parts) > 1 else ""

        # Parse status
        status_match = re.match(r"HTTP/\d\.\d\s+(\d+)", header_block)
        status = int(status_match.group(1)) if status_match else 0

        # Parse headers
        headers = {}
        for line in header_block.split("\r\n")[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()

        return status, body, headers
    except Exception:
        return 0, "", {}


class Check(Plugin):
    async def run(self, target: str, ctx) -> PluginResult:
        ports = ctx.get("net.open_ports", []) or []
        http_data = (ctx.get("fingerprint.http", {}) or {}).get("http", [])
        target_raw = ctx.get("target_raw", target)
        scan_type = ctx.get("scan_type", "internal")
        findings = []
        found_keys = []

        # ── Step 1: Determine base URLs to scan ────────────────────────
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
            return PluginResult(artifacts={"web.api_keys": []})

        # ── Step 2: Fetch pages and scan for keys ──────────────────────
        urls_to_check = set()
        for base in base_urls[:3]:  # Limit to 3 base URLs
            urls_to_check.add(base + "/")
            for endpoint in _SENSITIVE_ENDPOINTS:
                urls_to_check.add(base + endpoint)

        # Fetch in parallel, batches of 10
        all_responses = []
        url_list = list(urls_to_check)
        for i in range(0, len(url_list), 10):
            batch = url_list[i:i + 10]
            results = await asyncio.gather(
                *[_fetch_url(u, timeout=8.0) for u in batch],
                return_exceptions=True,
            )
            for url, result in zip(batch, results):
                if isinstance(result, Exception):
                    continue
                status, body, headers = result
                if status in (200, 201) and len(body) > 10:
                    all_responses.append((url, body, headers))

        # ── Step 3: Scan responses for API key patterns ────────────────
        seen_keys = set()
        for url, body, headers in all_responses:
            # Limit scanning to first 500KB
            scan_text = body[:512000]

            for name, pattern, severity, confidence, ref_url in _KEY_PATTERNS:
                matches = re.findall(pattern, scan_text, re.I)
                for match in matches:
                    # Dedup by (name, match_value)
                    key_id = f"{name}:{match[:20]}"
                    if key_id in seen_keys:
                        continue
                    seen_keys.add(key_id)

                    if not _is_likely_real_key(match, name):
                        continue

                    # Mask the key for evidence
                    if len(match) > 12:
                        masked = match[:6] + "..." + match[-4:]
                    else:
                        masked = match[:4] + "..."

                    fp = stable_fingerprint(target, META.plugin_id, name, match[:16])
                    findings.append(Finding(
                        severity=severity,
                        plugin_id=META.plugin_id,
                        title=f"{name} exposed in {_short_path(url)}",
                        description=(
                            f"A {name} was found exposed in the HTTP response from {url}. "
                            f"Leaked credentials allow unauthorized access to external services."
                        ),
                        evidence=f"type={name} value={masked} url={url}",
                        affected=target,
                        fingerprint=fp,
                        confidence=confidence,
                        remediation=(
                            f"[AFFECTED] {name} exposed at {url}\n\n"
                            f"[IMMEDIATE ACTION]\n"
                            f"1. Revoke this key/token immediately\n"
                            f"2. Generate a new key/token\n"
                            f"3. Update all services using the old key\n\n"
                            f"[PREVENTION]\n"
                            f"- Never hardcode secrets in source code or config files\n"
                            f"- Use environment variables or a secrets manager (AWS Secrets Manager, HashiCorp Vault)\n"
                            f"- Add secret scanning to your CI/CD pipeline (e.g., git-secrets, trufflehog)\n"
                            f"- Add sensitive files to .gitignore\n\n"
                            f"[REFERENCE] {ref_url}"
                        ),
                        references=[ref_url],
                    ))

                    found_keys.append({
                        "type": name,
                        "masked_value": masked,
                        "url": url,
                        "severity": severity,
                        "confidence": confidence,
                    })

        # ── Step 4: Check for exposed .env file content ────────────────
        for url, body, headers in all_responses:
            if "/.env" in url and _looks_like_env_file(body):
                env_keys = re.findall(r"^([A-Z_]{3,})=(.+)$", body[:4000], re.M)
                sensitive_env = [k for k, v in env_keys if any(
                    s in k.upper() for s in ["SECRET", "KEY", "TOKEN", "PASSWORD", "PASS", "AUTH", "PRIVATE"]
                )]
                if sensitive_env:
                    fp = stable_fingerprint(target, META.plugin_id, "env_file", url)
                    findings.append(Finding(
                        severity="critical",
                        plugin_id=META.plugin_id,
                        title=f"Environment file exposed: {_short_path(url)}",
                        description=(
                            f"The environment file at {url} is publicly accessible and contains "
                            f"{len(sensitive_env)} sensitive variable(s): {', '.join(sensitive_env[:5])}"
                        ),
                        evidence=f"url={url} sensitive_vars={sensitive_env[:10]} total_vars={len(env_keys)}",
                        affected=target,
                        fingerprint=fp,
                        confidence=0.95,
                        remediation=(
                            f"[CRITICAL] Environment file is publicly accessible\n\n"
                            f"[IMMEDIATE ACTION]\n"
                            f"1. Block access to .env files in your web server config\n"
                            f"2. Rotate ALL secrets found in this file\n\n"
                            f"[NGINX] location ~ /\\.env {{ deny all; return 404; }}\n"
                            f"[APACHE] <FilesMatch \"^\\.env\"> Require all denied </FilesMatch>\n\n"
                            f"[SENSITIVE VARS FOUND] {', '.join(sensitive_env[:10])}"
                        ),
                        references=["https://owasp.org/www-project-web-security-testing-guide/"],
                    ))

        return PluginResult(
            findings=findings,
            artifacts={"web.api_keys": found_keys},
        )


def _short_path(url: str) -> str:
    """Extract just the path from a URL for display."""
    parsed = urllib.parse.urlparse(url)
    return parsed.path or "/"


def _looks_like_env_file(body: str) -> bool:
    """Check if response body looks like a .env file."""
    lines = body.strip().split("\n")[:20]
    env_pattern = re.compile(r"^[A-Z_][A-Z0-9_]*=")
    matches = sum(1 for line in lines if env_pattern.match(line.strip()))
    return matches >= 3

