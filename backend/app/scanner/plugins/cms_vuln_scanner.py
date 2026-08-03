"""
CMS Vulnerability Scanner Plugin
Detects common security misconfigurations and known vulnerability indicators
in WordPress, Drupal, and Joomla installations.

Safety: All probes are GET-only and read-only. No modifications are made
to the target system.
"""
import asyncio
import re

import httpx

from app.scanner.plugins.base import Plugin, PluginMeta, PluginResult, Finding
from app.scanner.context import stable_fingerprint

META = PluginMeta(
    plugin_id="web.cms_vuln_scanner",
    name="CMS Vulnerability Scanner",
    category="web",
    depends_on=["fingerprint.web.tech", "fingerprint.deep"],
    consumes=["fingerprint.webtech", "fingerprint.deep"],
    provides=["web.cms_vulns"],
    enabled_by_default=True,
    timeout_seconds=30.0,
)

# ── WordPress vulnerable plugin paths (commonly exploited) ────────────
_WP_PLUGIN_READMES = [
    "contact-form-7",
    "elementor",
    "wpforms-lite",
    "classic-editor",
    "akismet",
    "yoast-seo",
    "woocommerce",
    "wordfence",
    "really-simple-ssl",
    "all-in-one-wp-migration",
    "updraftplus",
    "wp-super-cache",
    "jetpack",
    "advanced-custom-fields",
    "duplicate-page",
]


async def _safe_get(client: httpx.AsyncClient, url: str) -> httpx.Response | None:
    """Perform a GET request, returning None on any error."""
    try:
        return await client.get(url)
    except Exception:
        return None


def _extract_stable_tag(text: str) -> str | None:
    """Extract 'Stable tag' version from a WordPress plugin readme.txt."""
    m = re.search(r"Stable tag:\s*([0-9][0-9.]*)", text, re.I)
    return m.group(1) if m else None


class Check(Plugin):
    async def run(self, target: str, ctx) -> PluginResult:
        webtech = ctx.get("fingerprint.webtech", []) or []
        deep = ctx.get("fingerprint.deep", []) or []
        http_data = (ctx.get("fingerprint.http", {}) or {}).get("http", [])
        target_raw = ctx.get("target_raw", target)
        findings: list[Finding] = []
        artifacts: dict = {"cms_vulns": []}

        # Determine which CMS(es) are detected
        all_techs = list(webtech) + (deep if isinstance(deep, list) else [])
        detected_cms = set()
        for t in all_techs:
            if isinstance(t, dict) and t.get("type") == "cms":
                detected_cms.add(t.get("name", "").lower())

        if not detected_cms:
            return PluginResult(artifacts={"web.cms_vulns": []})

        # Determine base URLs
        base_urls = []
        if re.match(r"^https?://", target_raw, re.I):
            base_urls.append(target_raw.rstrip("/"))
        else:
            for item in http_data:
                url = item.get("url", "")
                if url:
                    base_urls.append(url.rstrip("/"))

        if not base_urls:
            return PluginResult(artifacts={"web.cms_vulns": []})

        try:
            async with httpx.AsyncClient(
                timeout=min(ctx.policy.timeout_seconds, 10),
                verify=False,
                follow_redirects=True,
                limits=httpx.Limits(max_connections=8),
            ) as client:
                for base_url in base_urls[:2]:
                    if "wordpress" in detected_cms:
                        wp_findings = await self._check_wordpress(
                            client, base_url, target
                        )
                        findings.extend(wp_findings)

                    if "drupal" in detected_cms:
                        drupal_findings = await self._check_drupal(
                            client, base_url, target
                        )
                        findings.extend(drupal_findings)

                    if "joomla" in detected_cms:
                        joomla_findings = await self._check_joomla(
                            client, base_url, target
                        )
                        findings.extend(joomla_findings)

        except Exception:
            pass

        for f in findings:
            artifacts["cms_vulns"].append({
                "title": f.title,
                "severity": f.severity,
            })

        return PluginResult(
            findings=findings,
            artifacts={"web.cms_vulns": artifacts["cms_vulns"]},
        )

    # ── WordPress checks ──────────────────────────────────────────────
    async def _check_wordpress(
        self, client: httpx.AsyncClient, base_url: str, target: str
    ) -> list[Finding]:
        findings: list[Finding] = []

        # 1. User enumeration via REST API
        r = await _safe_get(client, f"{base_url}/wp-json/wp/v2/users")
        if r and r.status_code == 200:
            try:
                users = r.json()
                if isinstance(users, list) and len(users) > 0:
                    usernames = [u.get("slug", "unknown") for u in users[:10]]
                    fp = stable_fingerprint(
                        target, META.plugin_id, "wp_user_enum", base_url
                    )
                    findings.append(Finding(
                        severity="medium",
                        plugin_id=META.plugin_id,
                        title="WordPress user enumeration via REST API",
                        description=(
                            f"The WordPress REST API at {base_url}/wp-json/wp/v2/users "
                            f"exposes user information. {len(users)} user(s) found: "
                            f"{', '.join(usernames[:5])}"
                        ),
                        evidence=f"url={base_url}/wp-json/wp/v2/users users={usernames[:5]}",
                        affected=target,
                        fingerprint=fp,
                        confidence=0.95,
                        remediation=(
                            "[AFFECTED] WordPress user enumeration is enabled\n\n"
                            "[FIX] Disable the users REST API endpoint:\n"
                            "  - Install a security plugin (e.g., Wordfence, iThemes Security) "
                            "and disable REST API user enumeration\n"
                            "  - Or add to functions.php:\n"
                            "    add_filter('rest_endpoints', function($endpoints) {\n"
                            "        unset($endpoints['/wp/v2/users']);\n"
                            "        return $endpoints;\n"
                            "    });\n\n"
                            "[WHY] Exposed usernames help attackers brute-force login credentials."
                        ),
                        references=[
                            "https://owasp.org/www-project-web-security-testing-guide/"
                        ],
                    ))
            except Exception:
                pass

        # 2. Debug log exposure
        r = await _safe_get(client, f"{base_url}/wp-content/debug.log")
        if r and r.status_code == 200 and len(r.text) > 50:
            # Check if it looks like a real debug log
            if "PHP" in r.text or "Warning" in r.text or "Error" in r.text:
                fp = stable_fingerprint(
                    target, META.plugin_id, "wp_debug_log", base_url
                )
                findings.append(Finding(
                    severity="high",
                    plugin_id=META.plugin_id,
                    title="WordPress debug.log exposed",
                    description=(
                        f"The WordPress debug log at {base_url}/wp-content/debug.log "
                        "is publicly accessible. This file may contain sensitive information "
                        "such as database errors, file paths, plugin errors, and stack traces."
                    ),
                    evidence=f"url={base_url}/wp-content/debug.log size={len(r.text)} snippet={r.text[:200]}",
                    affected=target,
                    fingerprint=fp,
                    confidence=0.95,
                    remediation=(
                        "[AFFECTED] WordPress debug.log is publicly accessible\n\n"
                        "[IMMEDIATE ACTION]\n"
                        "1. Delete or move debug.log outside the web root\n"
                        "2. Disable WP_DEBUG_LOG in wp-config.php for production:\n"
                        "   define('WP_DEBUG', false);\n"
                        "   define('WP_DEBUG_LOG', false);\n\n"
                        "[PREVENTION]\n"
                        "- Block access to log files in your web server config:\n"
                        "  Nginx: location ~* debug\\.log$ { deny all; return 404; }\n"
                        "  Apache: <Files debug.log> Require all denied </Files>"
                    ),
                    references=[
                        "https://wordpress.org/documentation/article/debugging-in-wordpress/"
                    ],
                ))

        # 3. wp-config.php backup
        for backup_ext in [".bak", ".old", ".save", ".orig", "~", ".swp"]:
            r = await _safe_get(
                client, f"{base_url}/wp-config.php{backup_ext}"
            )
            if r and r.status_code == 200 and (
                "DB_NAME" in r.text or "DB_PASSWORD" in r.text or "AUTH_KEY" in r.text
            ):
                fp = stable_fingerprint(
                    target, META.plugin_id, "wp_config_backup", base_url, backup_ext
                )
                findings.append(Finding(
                    severity="critical",
                    plugin_id=META.plugin_id,
                    title=f"WordPress wp-config.php backup exposed ({backup_ext})",
                    description=(
                        f"A backup of wp-config.php was found at "
                        f"{base_url}/wp-config.php{backup_ext}. This file contains "
                        "database credentials, authentication keys, and other secrets."
                    ),
                    evidence=f"url={base_url}/wp-config.php{backup_ext}",
                    affected=target,
                    fingerprint=fp,
                    confidence=0.98,
                    remediation=(
                        "[CRITICAL] WordPress configuration backup is publicly accessible\n\n"
                        "[IMMEDIATE ACTION]\n"
                        "1. Delete ALL backup copies of wp-config.php from the web root\n"
                        "2. Rotate ALL credentials found in the file:\n"
                        "   - Database password\n"
                        "   - Authentication keys and salts\n"
                        "   - Any API keys\n\n"
                        "[PREVENTION]\n"
                        "- Block access to PHP backup files in your web server config:\n"
                        "  Nginx: location ~* \\.(bak|old|save|orig|swp)$ { deny all; }\n"
                        "  Apache: <FilesMatch '\\.(bak|old|save|orig|swp)$'> "
                        "Require all denied </FilesMatch>"
                    ),
                    references=[
                        "https://owasp.org/www-project-web-security-testing-guide/"
                    ],
                ))
                break  # Only report the first backup found

        # 4. XML-RPC enabled
        r = await _safe_get(client, f"{base_url}/xmlrpc.php")
        if r and r.status_code == 200 and "XML-RPC server accepts POST requests only" in r.text:
            fp = stable_fingerprint(
                target, META.plugin_id, "wp_xmlrpc", base_url
            )
            findings.append(Finding(
                severity="medium",
                plugin_id=META.plugin_id,
                title="WordPress XML-RPC enabled",
                description=(
                    f"XML-RPC is enabled at {base_url}/xmlrpc.php. This endpoint can be "
                    "exploited for brute-force attacks (wp.getUsersBlogs), DDoS amplification "
                    "(pingback), and credential stuffing using the system.multicall method."
                ),
                evidence=f"url={base_url}/xmlrpc.php status=200",
                affected=target,
                fingerprint=fp,
                confidence=0.95,
                remediation=(
                    "[AFFECTED] WordPress XML-RPC is enabled\n\n"
                    "[FIX] Disable XML-RPC if not needed:\n"
                    "  - Nginx: location = /xmlrpc.php { deny all; return 403; }\n"
                    "  - Apache: <Files xmlrpc.php> Require all denied </Files>\n"
                    "  - Or add to functions.php:\n"
                    "    add_filter('xmlrpc_enabled', '__return_false');\n\n"
                    "[NOTE] XML-RPC is required for Jetpack, WordPress mobile app, "
                    "and some pingback functionality. Disable only if not needed."
                ),
                references=[
                    "https://kinsta.com/blog/xmlrpc-php/"
                ],
            ))

        # 5. wp-content/uploads directory listing
        r = await _safe_get(client, f"{base_url}/wp-content/uploads/")
        if r and r.status_code == 200 and (
            "Index of" in r.text or "<title>Index" in r.text
        ):
            fp = stable_fingerprint(
                target, META.plugin_id, "wp_uploads_listing", base_url
            )
            findings.append(Finding(
                severity="medium",
                plugin_id=META.plugin_id,
                title="WordPress uploads directory listing enabled",
                description=(
                    f"Directory listing is enabled at {base_url}/wp-content/uploads/. "
                    "Attackers can browse all uploaded files, potentially finding "
                    "sensitive documents, backup files, or private media."
                ),
                evidence=f"url={base_url}/wp-content/uploads/ directory_listing=true",
                affected=target,
                fingerprint=fp,
                confidence=0.95,
                remediation=(
                    "[AFFECTED] Directory listing enabled on uploads\n\n"
                    "[FIX] Disable directory listing:\n"
                    "  Nginx: autoindex off; (in the location block)\n"
                    "  Apache: Options -Indexes (in .htaccess or httpd.conf)\n\n"
                    "  Or add an empty index.php to wp-content/uploads/:\n"
                    "    <?php // Silence is golden."
                ),
                references=[
                    "https://owasp.org/www-project-web-security-testing-guide/"
                ],
            ))

        # 6. Check common vulnerable plugin versions
        plugin_tasks = []
        for plugin_slug in _WP_PLUGIN_READMES:
            url = f"{base_url}/wp-content/plugins/{plugin_slug}/readme.txt"
            plugin_tasks.append((plugin_slug, _safe_get(client, url)))

        results = await asyncio.gather(
            *[task for _, task in plugin_tasks], return_exceptions=True
        )

        for (plugin_slug, _), result in zip(plugin_tasks, results):
            if isinstance(result, Exception) or result is None:
                continue
            if result.status_code == 200 and "Stable tag" in result.text:
                version = _extract_stable_tag(result.text)
                if version:
                    fp = stable_fingerprint(
                        target, META.plugin_id, "wp_plugin", plugin_slug, version
                    )
                    findings.append(Finding(
                        severity="info",
                        plugin_id=META.plugin_id,
                        title=f"WordPress plugin detected: {plugin_slug} v{version}",
                        description=(
                            f"WordPress plugin '{plugin_slug}' version {version} was "
                            f"detected via its readme.txt file. Check if this version "
                            "has known vulnerabilities."
                        ),
                        evidence=f"plugin={plugin_slug} version={version} url={base_url}/wp-content/plugins/{plugin_slug}/readme.txt",
                        affected=target,
                        fingerprint=fp,
                        confidence=0.90,
                        remediation=(
                            f"[DETECTED] {plugin_slug} v{version}\n\n"
                            f"[ACTION]\n"
                            f"1. Check for known vulnerabilities: "
                            f"https://wpscan.com/plugins/{plugin_slug}\n"
                            f"2. Update to the latest version if outdated\n"
                            f"3. Remove the plugin if not actively used\n\n"
                            f"[PREVENTION]\n"
                            f"- Enable automatic plugin updates in WordPress\n"
                            f"- Block access to readme.txt files:\n"
                            f"  Nginx: location ~* /readme\\.txt$ {{ deny all; }}"
                        ),
                        references=[
                            f"https://wpscan.com/plugins/{plugin_slug}"
                        ],
                    ))

        return findings

    # ── Drupal checks ─────────────────────────────────────────────────
    async def _check_drupal(
        self, client: httpx.AsyncClient, base_url: str, target: str
    ) -> list[Finding]:
        findings: list[Finding] = []

        # 1. CHANGELOG.txt version disclosure
        for changelog_path in ["/CHANGELOG.txt", "/core/CHANGELOG.txt"]:
            r = await _safe_get(client, f"{base_url}{changelog_path}")
            if r and r.status_code == 200 and "Drupal" in r.text:
                # Try to extract version
                version = None
                m = re.search(r"Drupal ([0-9]+\.[0-9.]+)", r.text)
                if m:
                    version = m.group(1)

                fp = stable_fingerprint(
                    target, META.plugin_id, "drupal_changelog", base_url,
                    changelog_path
                )
                findings.append(Finding(
                    severity="low",
                    plugin_id=META.plugin_id,
                    title=f"Drupal CHANGELOG.txt exposed{' (v' + version + ')' if version else ''}",
                    description=(
                        f"Drupal's CHANGELOG.txt is accessible at "
                        f"{base_url}{changelog_path}. "
                        f"{'Version ' + version + ' detected. ' if version else ''}"
                        "This allows attackers to identify the exact Drupal version "
                        "and find matching exploits."
                    ),
                    evidence=f"url={base_url}{changelog_path} version={version}",
                    affected=target,
                    fingerprint=fp,
                    confidence=0.90,
                    remediation=(
                        "[AFFECTED] Drupal changelog is publicly accessible\n\n"
                        "[FIX] Remove or restrict access to CHANGELOG.txt:\n"
                        "  Nginx: location ~* CHANGELOG\\.txt$ { deny all; return 404; }\n"
                        "  Apache: <Files CHANGELOG.txt> Require all denied </Files>\n\n"
                        "[ALSO] Update Drupal to the latest version: "
                        "https://www.drupal.org/project/drupal/releases"
                    ),
                    references=[
                        "https://www.drupal.org/security"
                    ],
                ))
                break

        # 2. Open user registration
        r = await _safe_get(client, f"{base_url}/user/register")
        if r and r.status_code == 200 and (
            'id="user-register-form"' in r.text
            or 'name="form_id" value="user_register_form"' in r.text
            or "Create new account" in r.text
        ):
            fp = stable_fingerprint(
                target, META.plugin_id, "drupal_open_reg", base_url
            )
            findings.append(Finding(
                severity="medium",
                plugin_id=META.plugin_id,
                title="Drupal open user registration enabled",
                description=(
                    f"User registration is open at {base_url}/user/register. "
                    "This allows anyone to create an account, which may not be "
                    "intended and could lead to unauthorized access."
                ),
                evidence=f"url={base_url}/user/register status=200 form_present=true",
                affected=target,
                fingerprint=fp,
                confidence=0.85,
                remediation=(
                    "[AFFECTED] Drupal allows open user registration\n\n"
                    "[FIX] Restrict registration (if not needed):\n"
                    "  Admin > Configuration > People > Account Settings\n"
                    "  Set 'Who can register accounts?' to 'Administrators only'\n\n"
                    "[IF REGISTRATION IS NEEDED]\n"
                    "  - Enable CAPTCHA or reCAPTCHA\n"
                    "  - Require email verification\n"
                    "  - Limit default permissions for new accounts"
                ),
                references=[
                    "https://www.drupal.org/docs/administering-a-drupal-site/managing-users"
                ],
            ))

        # 3. Unauthenticated admin config access
        r = await _safe_get(client, f"{base_url}/admin/config")
        if r and r.status_code == 200 and (
            "Configuration" in r.text
            and ("System" in r.text or "People" in r.text)
            and "Access denied" not in r.text
        ):
            fp = stable_fingerprint(
                target, META.plugin_id, "drupal_admin_config", base_url
            )
            findings.append(Finding(
                severity="high",
                plugin_id=META.plugin_id,
                title="Drupal admin configuration accessible without authentication",
                description=(
                    f"The Drupal admin configuration page at {base_url}/admin/config "
                    "is accessible without authentication. This exposes system "
                    "configuration details and may allow unauthorized changes."
                ),
                evidence=f"url={base_url}/admin/config status=200",
                affected=target,
                fingerprint=fp,
                confidence=0.80,
                remediation=(
                    "[CRITICAL] Drupal admin is accessible without authentication\n\n"
                    "[IMMEDIATE ACTION]\n"
                    "1. Check user permissions: Admin > People > Permissions\n"
                    "2. Ensure 'anonymous user' role has no admin permissions\n"
                    "3. Restrict admin paths by IP:\n"
                    "  Nginx: location ^~ /admin { allow 10.0.0.0/8; deny all; }\n\n"
                    "[PREVENTION]\n"
                    "- Review permissions after module updates\n"
                    "- Enable login flood control"
                ),
                references=[
                    "https://www.drupal.org/docs/security-in-drupal"
                ],
            ))

        return findings

    # ── Joomla checks ─────────────────────────────────────────────────
    async def _check_joomla(
        self, client: httpx.AsyncClient, base_url: str, target: str
    ) -> list[Finding]:
        findings: list[Finding] = []

        # 1. Version disclosure via manifest
        r = await _safe_get(
            client,
            f"{base_url}/administrator/manifests/files/joomla.xml"
        )
        if r and r.status_code == 200 and "<version>" in r.text:
            m = re.search(r"<version>([0-9.]+)</version>", r.text)
            version = m.group(1) if m else "unknown"
            fp = stable_fingerprint(
                target, META.plugin_id, "joomla_version", base_url
            )
            findings.append(Finding(
                severity="low",
                plugin_id=META.plugin_id,
                title=f"Joomla version disclosed: {version}",
                description=(
                    f"The Joomla manifest file at "
                    f"{base_url}/administrator/manifests/files/joomla.xml "
                    f"reveals Joomla version {version}. This helps attackers "
                    "identify version-specific vulnerabilities."
                ),
                evidence=f"url={base_url}/administrator/manifests/files/joomla.xml version={version}",
                affected=target,
                fingerprint=fp,
                confidence=0.95,
                remediation=(
                    f"[AFFECTED] Joomla version {version} disclosed\n\n"
                    "[FIX] Block access to XML manifest files:\n"
                    "  Nginx: location ~* \\.xml$ { deny all; return 404; }\n"
                    "  Apache: <FilesMatch '\\.xml$'> Require all denied </FilesMatch>\n\n"
                    "[ALSO] Update Joomla to the latest version: "
                    "https://downloads.joomla.org/"
                ),
                references=[
                    "https://developer.joomla.org/security-centre.html"
                ],
            ))

        # 2. Configuration backup
        for backup_ext in [".bak", ".old", ".save", ".dist"]:
            r = await _safe_get(
                client, f"{base_url}/configuration.php{backup_ext}"
            )
            if r and r.status_code == 200 and (
                "JConfig" in r.text or "$host" in r.text or "$db" in r.text
            ):
                fp = stable_fingerprint(
                    target, META.plugin_id, "joomla_config_backup", base_url,
                    backup_ext
                )
                findings.append(Finding(
                    severity="critical",
                    plugin_id=META.plugin_id,
                    title=f"Joomla configuration.php backup exposed ({backup_ext})",
                    description=(
                        f"A backup of configuration.php was found at "
                        f"{base_url}/configuration.php{backup_ext}. This file "
                        "contains database credentials, secret keys, and other "
                        "sensitive configuration."
                    ),
                    evidence=f"url={base_url}/configuration.php{backup_ext}",
                    affected=target,
                    fingerprint=fp,
                    confidence=0.98,
                    remediation=(
                        "[CRITICAL] Joomla configuration backup is publicly accessible\n\n"
                        "[IMMEDIATE ACTION]\n"
                        "1. Delete ALL backup copies of configuration.php\n"
                        "2. Rotate ALL credentials found in the file:\n"
                        "   - Database password ($password)\n"
                        "   - Secret key ($secret)\n"
                        "   - FTP credentials (if configured)\n\n"
                        "[PREVENTION]\n"
                        "- Block access to PHP backup files:\n"
                        "  Nginx: location ~* \\.(bak|old|save|dist)$ { deny all; }\n"
                        "  Apache: <FilesMatch '\\.(bak|old|save|dist)$'> "
                        "Require all denied </FilesMatch>"
                    ),
                    references=[
                        "https://owasp.org/www-project-web-security-testing-guide/"
                    ],
                ))
                break

        # 3. htaccess.txt exposure
        r = await _safe_get(client, f"{base_url}/htaccess.txt")
        if r and r.status_code == 200 and (
            "RewriteEngine" in r.text or "mod_rewrite" in r.text
        ):
            fp = stable_fingerprint(
                target, META.plugin_id, "joomla_htaccess", base_url
            )
            findings.append(Finding(
                severity="low",
                plugin_id=META.plugin_id,
                title="Joomla htaccess.txt exposed",
                description=(
                    f"The htaccess.txt file at {base_url}/htaccess.txt is "
                    "publicly accessible. This file reveals server configuration "
                    "rules and rewrite patterns used by the application."
                ),
                evidence=f"url={base_url}/htaccess.txt status=200",
                affected=target,
                fingerprint=fp,
                confidence=0.85,
                remediation=(
                    "[AFFECTED] Joomla htaccess.txt is publicly accessible\n\n"
                    "[FIX] Either rename htaccess.txt to .htaccess (if using Apache) "
                    "or block access to .txt files:\n"
                    "  Nginx: location ~* htaccess\\.txt$ { deny all; return 404; }\n"
                    "  Apache: <Files htaccess.txt> Require all denied </Files>\n\n"
                    "[NOTE] The htaccess.txt is a Joomla template for .htaccess and "
                    "is not used by the server directly."
                ),
                references=[
                    "https://docs.joomla.org/Htaccess_examples_(security)"
                ],
            ))

        return findings
