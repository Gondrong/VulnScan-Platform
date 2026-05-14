"""
LDAP Injection Scanner
Tests input parameters for LDAP injection vulnerabilities and checks
for anonymous LDAP bind on discovered LDAP ports.
"""
import asyncio
import re
import ssl
import struct
import urllib.parse

from app.scanner.plugins.base import Plugin, PluginMeta, PluginResult, Finding
from app.scanner.context import stable_fingerprint

META = PluginMeta(
    plugin_id="web.ldap_injection",
    name="LDAP Injection Scanner",
    category="web",
    depends_on=["fingerprint.http", "net.port.discovery.v2"],
    consumes=["fingerprint.http", "net.open_ports"],
    provides=["web.ldap_findings"],
    enabled_by_default=True,
    timeout_seconds=30.0,
)

# LDAP ports
_LDAP_PORTS = [389, 636, 3268, 3269]

# LDAP injection payloads
_LDAP_PAYLOADS = [
    ("*", "wildcard_match"),
    ("*)(&", "filter_break"),
    ("*)(|(objectClass=*)", "or_injection"),
    ("admin)(&)", "admin_bypass"),
    ("*)(objectClass=*))(&(objectClass=void", "nested_filter"),
    (")(cn=*))(|(cn=*", "cn_enum"),
]

# LDAP error patterns in HTTP responses
_LDAP_ERROR_PATTERNS = [
    r"ldap_search",
    r"ldap_bind",
    r"invalid\s+dn",
    r"bad\s+search\s+filter",
    r"javax\.naming",
    r"LDAPException",
    r"ldap_err2string",
    r"invalid\s+ldap",
    r"operations?\s+error.*ldap",
    r"supplied\s+argument.*ldap",
]

# Common login/search endpoints to test
_TEST_ENDPOINTS = [
    ("/login", "POST", "username"),
    ("/api/login", "POST", "username"),
    ("/auth", "POST", "user"),
    ("/search", "GET", "q"),
    ("/api/search", "GET", "query"),
    ("/api/users", "GET", "filter"),
    ("/ldap/search", "GET", "cn"),
]


async def _http_request(host: str, port: int, method: str, path: str,
                        params: dict = None, body: str = "",
                        use_tls: bool = False, timeout: float = 5.0) -> tuple[int, str]:
    """Send HTTP request, return (status, body)."""
    try:
        if params and method == "GET":
            path += "?" + urllib.parse.urlencode(params)

        if use_tls:
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
            "Accept": "*/*",
            "Connection": "close",
        }
        if method == "POST":
            if not body:
                body = urllib.parse.urlencode(params or {})
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            headers["Content-Length"] = str(len(body))

        request = f"{method} {path} HTTP/1.1\r\n"
        request += "".join(f"{k}: {v}\r\n" for k, v in headers.items())
        request += f"\r\n{body}"

        writer.write(request.encode())
        await writer.drain()

        response = await asyncio.wait_for(reader.read(16384), timeout=timeout)
        writer.close()

        text = response.decode("utf-8", errors="ignore")
        parts = text.split("\r\n\r\n", 1)
        header_block = parts[0] if parts else ""
        resp_body = parts[1] if len(parts) > 1 else ""

        status_match = re.match(r"HTTP/\d\.\d\s+(\d+)", header_block)
        status = int(status_match.group(1)) if status_match else 0

        return status, resp_body
    except Exception:
        return 0, ""


async def _test_ldap_port(host: str, port: int, timeout: float = 5.0) -> tuple[bool, bool]:
    """Test if LDAP port is open and allows anonymous bind. Returns (open, anon_bind)."""
    try:
        if port in (636, 3269):
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

        # Send LDAP Simple Bind Request (anonymous — empty DN and password)
        # LDAP BindRequest: version=3, name="", auth=simple("")
        bind_request = bytes([
            0x30, 0x0c,             # SEQUENCE
            0x02, 0x01, 0x01,       # MessageID: 1
            0x60, 0x07,             # BindRequest
            0x02, 0x01, 0x03,       # Version: 3
            0x04, 0x00,             # Name: "" (empty = anonymous)
            0x80, 0x00,             # Auth: simple, "" (empty password)
        ])

        writer.write(bind_request)
        await writer.drain()

        data = await asyncio.wait_for(reader.read(1024), timeout=timeout)
        writer.close()

        if not data or len(data) < 10:
            return True, False

        # Parse LDAP BindResponse — look for resultCode
        # resultCode 0 = success (anonymous bind allowed)
        # resultCode 49 = invalidCredentials (anonymous denied)
        if data[0] == 0x30 and len(data) > 9:
            # Find resultCode in the response
            for i in range(5, min(len(data) - 2, 20)):
                if data[i] == 0x0a and data[i + 1] == 0x01:
                    result_code = data[i + 2]
                    return True, result_code == 0

        return True, False
    except Exception:
        return False, False


class Check(Plugin):
    async def run(self, target: str, ctx) -> PluginResult:
        ports = ctx.get("net.open_ports", []) or []
        http_data = (ctx.get("fingerprint.http", {}) or {}).get("http", [])
        target_raw = ctx.get("target_raw", target)
        findings = []
        ldap_results = []

        # ── Check 1: LDAP port anonymous bind ──────────────────────────
        ldap_ports = [p for p in ports if p in _LDAP_PORTS]
        for port in ldap_ports:
            is_open, anon_bind = await _test_ldap_port(target, port)
            if is_open and anon_bind:
                fp = stable_fingerprint(target, META.plugin_id, "anon_bind", str(port))
                findings.append(Finding(
                    severity="critical",
                    plugin_id=META.plugin_id,
                    title=f"LDAP anonymous bind allowed on port {port}",
                    description=(
                        f"The LDAP server at {target}:{port} accepts anonymous bind requests. "
                        f"An attacker can enumerate all directory objects (users, groups, OUs) "
                        f"without authentication."
                    ),
                    evidence=f"host={target} port={port} anonymous_bind=true",
                    affected=target,
                    fingerprint=fp,
                    confidence=0.95,
                    remediation=(
                        f"[CRITICAL] LDAP anonymous bind on port {port}\n\n"
                        f"[FIX]\n"
                        f"  Active Directory: Set 'Network access: Restrict anonymous access to Named Pipes and Shares'\n"
                        f"  OpenLDAP: Set 'olcRequires: authc' or 'disallow bind_anon'\n"
                        f"  389 DS: Set 'nsslapd-allow-anonymous-access: off'\n\n"
                        f"[IMPACT] Full directory enumeration — users, groups, password policies, service accounts"
                    ),
                    references=["https://attack.mitre.org/techniques/T1087/002/"],
                ))
                ldap_results.append({"port": port, "anonymous_bind": True})
            elif is_open:
                ldap_results.append({"port": port, "anonymous_bind": False})

        # ── Check 2: LDAP injection in web endpoints ───────────────────
        base_urls = []
        if re.match(r"^https?://", target_raw, re.I):
            base_urls.append(target_raw.rstrip("/"))
        else:
            for item in http_data:
                url = item.get("url", "")
                if url:
                    base_urls.append(url.rstrip("/"))

        for base in base_urls[:2]:
            parsed = urllib.parse.urlparse(base)
            host = parsed.hostname or target
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            use_tls = parsed.scheme == "https"

            for path, method, param_name in _TEST_ENDPOINTS:
                # Baseline request with normal value
                baseline_status, baseline_body = await _http_request(
                    host, port, method, path,
                    params={param_name: "testuser123"} if method == "GET" else None,
                    body=f"{param_name}=testuser123&password=test" if method == "POST" else "",
                    use_tls=use_tls,
                )
                if baseline_status in (0, 404, 405):
                    continue

                # Pre-check: if the baseline response already contains
                # LDAP error patterns, this endpoint naturally shows
                # LDAP-related content and error detection is unreliable.
                baseline_has_ldap_errors = any(
                    re.search(pat, baseline_body, re.I)
                    for pat in _LDAP_ERROR_PATTERNS
                )

                # Test each payload
                for payload, payload_type in _LDAP_PAYLOADS:
                    inj_status, inj_body = await _http_request(
                        host, port, method, path,
                        params={param_name: payload} if method == "GET" else None,
                        body=f"{param_name}={urllib.parse.quote(payload)}&password=test" if method == "POST" else "",
                        use_tls=use_tls,
                    )

                    if inj_status == 0:
                        continue

                    # Check for LDAP error messages in response,
                    # but only if the baseline is clean
                    if baseline_has_ldap_errors:
                        break  # Skip — baseline already has LDAP errors
                    for pattern in _LDAP_ERROR_PATTERNS:
                        if re.search(pattern, inj_body, re.I):
                            fp = stable_fingerprint(target, META.plugin_id, "injection", path, param_name)
                            findings.append(Finding(
                                severity="high",
                                plugin_id=META.plugin_id,
                                title=f"LDAP injection: {method} {path} ({param_name})",
                                description=(
                                    f"The parameter '{param_name}' at {path} is vulnerable to LDAP injection. "
                                    f"The server returned an LDAP error when a malformed filter was injected."
                                ),
                                evidence=(
                                    f"url={base}{path} param={param_name} payload={payload} "
                                    f"type={payload_type} status={inj_status} "
                                    f"error_pattern={pattern}"
                                ),
                                affected=target,
                                fingerprint=fp,
                                confidence=0.85,
                                remediation=(
                                    f"[AFFECTED] LDAP injection at {path} via '{param_name}'\n\n"
                                    f"[FIX]\n"
                                    f"1. Sanitize all user input before LDAP queries\n"
                                    f"2. Escape LDAP special characters: * ( ) \\ / NUL\n"
                                    f"3. Use parameterized LDAP queries\n"
                                    f"4. Implement input validation (whitelist allowed characters)\n\n"
                                    f"[IMPACT] Authentication bypass, directory enumeration, data exfiltration"
                                ),
                                references=["https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html"],
                            ))
                            ldap_results.append({"type": "injection", "path": path, "param": param_name})
                            break
                    else:
                        continue
                    break  # Found injection on this endpoint, move to next

        return PluginResult(findings=findings, artifacts={"web.ldap_findings": ldap_results})
