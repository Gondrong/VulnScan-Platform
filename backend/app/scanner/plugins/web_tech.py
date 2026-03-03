import re

import httpx

from app.scanner.plugins.base import Plugin, PluginMeta, PluginResult, Finding
from app.scanner.context import stable_fingerprint

META = PluginMeta(
    plugin_id="fingerprint.web.tech",
    name="Web Technology Detection",
    category="fingerprint",
    depends_on=["fingerprint.http"],
    consumes=["fingerprint.http"],
    provides=["fingerprint.webtech"],
    enabled_by_default=True,
    timeout_seconds=10.0,
)

CMS_PATTERNS = [
    ("wordpress", r"wp-content|wp-includes|wordpress"),
    ("drupal", r'Drupal\.settings|drupal\.js|sites/default/files'),
    ("joomla", r"Joomla!|/components/com_"),
    ("magento", r"Mage\.Cookies|magento"),
]
FRAMEWORK_PATTERNS = [
    ("laravel", r"laravel_session|XSRF-TOKEN"),
    ("nextjs", r"__NEXT_DATA__|/_next/static"),
    ("react", r"data-reactroot|react-dom"),
    ("vue", r"__VUE__|data-v-app"),
    ("django", r"csrfmiddlewaretoken|django"),
    ("angular", r"ng-app|ng-version"),
    ("jquery", r"jquery[\./]|jQuery"),
    ("bootstrap", r"bootstrap\.min|bootstrap\.css"),
]
HEADER_PATTERNS = [
    ("nginx", r"\bnginx\b", "server"),
    ("apache", r"\bapache\b", "server"),
    ("iis", r"\biis\b|microsoft-iis", "server"),
    ("php", r"\bphp\b", "x-powered-by"),
    ("asp.net", r"asp\.net", "x-powered-by"),
]

# Remediation guidance for detected technologies
TECH_REMEDIATION = {
    "wordpress": "Keep WordPress core, themes, and plugins updated. Remove unused plugins/themes. Use a WAF and enable 2FA for admin accounts. Hide wp-login.php from public access.",
    "drupal": "Keep Drupal core and contributed modules updated. Subscribe to Drupal security advisories. Restrict admin access and audit permissions.",
    "joomla": "Update Joomla and all extensions to latest versions. Restrict admin panel access. Enable 2FA and review user permissions.",
    "magento": "Apply all Adobe Commerce security patches. Enable 2FA, restrict admin access, and audit third-party extensions.",
    "laravel": "Update Laravel and dependencies (composer update). Set APP_DEBUG=false in production. Rotate APP_KEY if compromised.",
    "nextjs": "Update Next.js and npm dependencies. Run 'npm audit fix'. Ensure API routes are properly authenticated.",
    "react": "Update React and dependencies. Review for XSS vulnerabilities in dangerouslySetInnerHTML usage.",
    "vue": "Update Vue.js and dependencies. Audit v-html usage for XSS risks.",
    "django": "Update Django to latest version. Review security middleware settings. Ensure DEBUG=False in production.",
    "angular": "Update Angular to latest version. Enable strict Content Security Policy. Review template injection risks.",
    "jquery": "Update jQuery to 3.x+ (older versions have known XSS vulnerabilities). Run 'npm audit'.",
    "bootstrap": "Update Bootstrap to latest version. Review for known XSS in tooltip/popover components in older versions.",
    "nginx": "Update nginx. Set 'server_tokens off' to hide version. Configure security headers (CSP, HSTS, X-Frame-Options).",
    "apache": "Update Apache. Set 'ServerTokens Prod' and 'ServerSignature Off'. Enable mod_security and mod_headers.",
    "iis": "Apply Windows updates for IIS. Remove server version headers. Enable request filtering.",
    "php": "Update PHP to latest supported version. Set 'expose_php = Off'. Disable dangerous functions in php.ini.",
    "asp.net": "Update .NET runtime. Set customErrors mode='On'. Remove X-Powered-By and X-AspNet-Version headers.",
}


class Check(Plugin):
    async def run(self, target: str, ctx) -> PluginResult:
        fp = ctx.get("fingerprint.http", {}) or {}
        http_items = fp.get("http", [])
        detected: list[dict] = []
        findings: list[Finding] = []

        for item in http_items:
            url = item.get("url")
            if not url:
                continue

            # Header-based detection
            server = (item.get("server") or "").lower()
            powered_by = (item.get("powered_by") or "").lower()
            for name, pat, header_field in HEADER_PATTERNS:
                val = server if header_field == "server" else powered_by
                if re.search(pat, val, re.I):
                    # Extract version if present
                    ver_match = re.search(rf"{name}[/: ]*([0-9][0-9.]+)", val, re.I)
                    version = ver_match.group(1) if ver_match else None
                    detected.append({
                        "type": "server", "name": name, "confidence": 0.85,
                        "version": version,
                    })

            # HTML-based detection
            try:
                async with httpx.AsyncClient(
                    timeout=min(ctx.policy.timeout_seconds, 8),
                    verify=False,
                    follow_redirects=True,
                    limits=httpx.Limits(max_connections=5),
                ) as client:
                    r = await client.get(url)
                    html = r.text or ""
                    headers_lower = {k.lower(): v for k, v in r.headers.items()}

                    for name, pat in CMS_PATTERNS:
                        if re.search(pat, html, re.I):
                            # Try to extract version
                            version = None
                            if name == "wordpress":
                                vm = re.search(r'content="WordPress ([0-9.]+)"', html)
                                if not vm:
                                    vm = re.search(r'ver=([0-9.]+)', html)
                                if vm:
                                    version = vm.group(1)
                            elif name == "drupal":
                                vm = re.search(r'Drupal ([0-9.]+)', html)
                                if vm:
                                    version = vm.group(1)
                            detected.append({
                                "type": "cms", "name": name, "confidence": 0.9,
                                "version": version,
                            })

                    for name, pat in FRAMEWORK_PATTERNS:
                        if re.search(pat, html, re.I) or re.search(pat, str(r.headers), re.I):
                            version = None
                            if name == "jquery":
                                vm = re.search(r'jquery[/-]([0-9][0-9.]+)', html, re.I)
                                if vm:
                                    version = vm.group(1)
                            elif name == "angular":
                                vm = re.search(r'ng-version="([0-9.]+)"', html)
                                if vm:
                                    version = vm.group(1)
                            elif name == "react":
                                vm = re.search(r'react(?:\.production\.min)?\.js[?/]v?([0-9.]+)', html, re.I)
                                if vm:
                                    version = vm.group(1)
                            detected.append({
                                "type": "framework", "name": name, "confidence": 0.75,
                                "version": version,
                            })

                    # Extra server headers from live response
                    srv = headers_lower.get("server", "").lower()
                    if srv:
                        for name, pat, _ in HEADER_PATTERNS:
                            if re.search(pat, srv, re.I):
                                ver_match = re.search(rf"{name}[/: ]*([0-9][0-9.]+)", srv, re.I)
                                version = ver_match.group(1) if ver_match else None
                                detected.append({
                                    "type": "server", "name": name, "confidence": 0.9,
                                    "version": version,
                                })

                    # Check for missing security headers
                    security_headers = {
                        "strict-transport-security": "HSTS not set — browsers won't enforce HTTPS",
                        "x-content-type-options": "X-Content-Type-Options not set — MIME sniffing possible",
                        "x-frame-options": "X-Frame-Options not set — clickjacking possible",
                        "content-security-policy": "Content-Security-Policy not set — XSS risk increased",
                    }
                    missing_headers = []
                    for hdr, desc in security_headers.items():
                        if hdr not in headers_lower:
                            missing_headers.append(desc)

                    if missing_headers:
                        findings.append(Finding(
                            severity="low",
                            plugin_id=META.plugin_id,
                            title=f"Missing security headers ({len(missing_headers)} headers)",
                            description=f"The web server at {url} is missing recommended security headers: " + "; ".join(missing_headers),
                            evidence=f"url={url} missing_headers={', '.join(h.split(' ')[0] for h in missing_headers)}",
                            affected=target,
                            fingerprint=stable_fingerprint(target, META.plugin_id, "missing_headers", url),
                            remediation=(
                                "Add the following security headers to your web server configuration:\n"
                                "- Strict-Transport-Security: max-age=31536000; includeSubDomains\n"
                                "- X-Content-Type-Options: nosniff\n"
                                "- X-Frame-Options: DENY (or SAMEORIGIN)\n"
                                "- Content-Security-Policy: default-src 'self'\n\n"
                                "For nginx: add_header directives in server block.\n"
                                "For Apache: Header set directives in .htaccess or httpd.conf."
                            ),
                        ))

            except Exception:
                pass

        # Deduplicate
        seen: set[tuple] = set()
        unique: list[dict] = []
        for d in detected:
            k = (d["type"], d["name"])
            if k not in seen:
                seen.add(k)
                unique.append(d)

        # Generate findings for detected technologies with remediation
        for d in unique:
            name = d["name"]
            tech_type = d["type"]
            version = d.get("version")
            ver_str = f" v{version}" if version else ""

            remediation = TECH_REMEDIATION.get(name, f"Keep {name} updated to the latest version and review vendor security advisories.")

            if version:
                remediation += f"\n\nDetected version: {version}. Check if this version has known vulnerabilities at https://nvd.nist.gov/."

            findings.append(Finding(
                severity="info",
                plugin_id=META.plugin_id,
                title=f"Detected {tech_type}: {name}{ver_str}",
                description=f"Web technology detected: {name}{ver_str} (type: {tech_type}, confidence: {d['confidence']:.0%})",
                evidence=f"technology={name} type={tech_type} version={version or 'unknown'} confidence={d['confidence']}",
                affected=target,
                fingerprint=stable_fingerprint(target, META.plugin_id, name, tech_type),
                remediation=remediation,
            ))

        return PluginResult(
            findings=findings,
            artifacts={"fingerprint.webtech": unique},
        )
