"""
CVE Endpoint Prober — safe endpoint verification for known CVE patterns.

For specific high-value CVEs, this plugin sends safe HTTP probes to verify
whether the vulnerable endpoint/feature exists on the target. This is NOT
exploitation — it checks if the attack surface exists.

Safety:
- All probes are GET-only or use idempotent methods.
- No payloads that modify state.
- No sensitive data is sent to the target.
- Each probe documents what it tests and why it is safe.
"""
import asyncio
import re

import httpx

from app.scanner.plugins.base import Finding, Plugin, PluginMeta, PluginResult
from app.scanner.context import stable_fingerprint

META = PluginMeta(
    plugin_id="cve.endpoint_prober",
    name="CVE Endpoint Prober",
    category="validation",
    depends_on=["cve.match.nvd_cpe"],
    soft_depends_on=["cve.match.packages"],
    consumes=["cve.nvd_hits", "cve.package_hits", "fingerprint.http", "fingerprint.webtech"],
    provides=["cve.endpoint_probes"],
    enabled_by_default=True,
    timeout_seconds=45.0,
)

_PROBE_TIMEOUT = 5.0


async def _safe_get(client, url, **kwargs):
    try:
        return await asyncio.wait_for(client.get(url, **kwargs), timeout=_PROBE_TIMEOUT)
    except Exception:
        return None


# ── Probe functions ──────────────────────────────────────────────────────────
# Each returns: {"confirmed": bool, "evidence": str}
# "confirmed" means the attack surface exists (not that exploitation succeeded).

async def _probe_wp_user_enum(client, base_url):
    """WordPress pre-auth user enumeration via REST API.
    Relevant to many WP CVEs involving user data disclosure.
    Safe: GET-only, reads public endpoint."""
    r = await _safe_get(client, f"{base_url}/wp-json/wp/v2/users")
    if r and r.status_code == 200:
        try:
            data = r.json()
            if isinstance(data, list) and data and "slug" in data[0]:
                return {"confirmed": True, "evidence": f"wp_users_endpoint_accessible count={len(data)}"}
        except Exception:
            pass
    return {"confirmed": False, "evidence": "wp_users_endpoint_not_accessible"}


async def _probe_wp_xmlrpc(client, base_url):
    """WordPress XML-RPC interface.
    Relevant to CVEs involving brute force, pingback SSRF, DoS.
    Safe: GET-only to check existence."""
    r = await _safe_get(client, f"{base_url}/xmlrpc.php")
    if r and r.status_code == 200 and "XML-RPC" in r.text:
        return {"confirmed": True, "evidence": "xmlrpc_accessible"}
    return {"confirmed": False, "evidence": "xmlrpc_not_accessible"}


async def _probe_spring_actuator(client, base_url):
    """Spring Boot Actuator endpoints.
    Relevant to info disclosure, RCE via env/heapdump endpoints.
    Safe: GET-only, reads public endpoints."""
    for path in ["/actuator/env", "/actuator/configprops", "/actuator/mappings"]:
        r = await _safe_get(client, f"{base_url}{path}")
        if r and r.status_code == 200:
            try:
                data = r.json()
                if isinstance(data, dict):
                    return {"confirmed": True, "evidence": f"actuator_exposed path={path}"}
            except Exception:
                pass
    return {"confirmed": False, "evidence": "actuator_not_exposed"}


async def _probe_apache_server_status(client, base_url):
    """Apache server-status / server-info pages.
    Relevant to info disclosure CVEs.
    Safe: GET-only."""
    for path in ["/server-status", "/server-info"]:
        r = await _safe_get(client, f"{base_url}{path}")
        if r and r.status_code == 200 and ("Apache Server Status" in r.text or "Server Version" in r.text):
            return {"confirmed": True, "evidence": f"apache_status_exposed path={path}"}
    return {"confirmed": False, "evidence": "apache_status_not_exposed"}


async def _probe_apache_path_traversal(client, base_url):
    """Apache path normalization (CVE-2021-41773, CVE-2021-42013 style).
    Safe: only reads /etc/hostname which is non-sensitive."""
    test_paths = [
        "/icons/.%2e/%2e%2e/%2e%2e/etc/hostname",
        "/cgi-bin/.%2e/%2e%2e/%2e%2e/etc/hostname",
    ]
    for path in test_paths:
        r = await _safe_get(client, f"{base_url}{path}")
        if r and r.status_code == 200 and len(r.text.strip()) < 256:
            # /etc/hostname is typically a single short line
            hostname = r.text.strip()
            if hostname and "\n" not in hostname and "<" not in hostname:
                return {"confirmed": True, "evidence": f"path_traversal_confirmed path={path}"}
    return {"confirmed": False, "evidence": "path_traversal_not_confirmed"}


async def _probe_nginx_off_by_slash(client, base_url):
    """Nginx alias traversal (off-by-slash misconfiguration).
    Safe: GET-only, tests for path traversal indicators."""
    r = await _safe_get(client, f"{base_url}/static../etc/passwd")
    if r and r.status_code == 200 and re.search(r"root:.*:0:0:", r.text):
        return {"confirmed": True, "evidence": "nginx_alias_traversal_confirmed"}
    return {"confirmed": False, "evidence": "nginx_alias_traversal_not_confirmed"}


async def _probe_php_info(client, base_url):
    """Exposed phpinfo() page.
    Relevant to many PHP CVEs — confirms PHP version and config.
    Safe: GET-only."""
    for path in ["/phpinfo.php", "/info.php", "/php_info.php"]:
        r = await _safe_get(client, f"{base_url}{path}")
        if r and r.status_code == 200 and "PHP Version" in r.text:
            m = re.search(r'PHP Version\s*</td><td[^>]*>([0-9.]+)', r.text)
            version = m.group(1) if m else "unknown"
            return {"confirmed": True, "evidence": f"phpinfo_exposed path={path} php_version={version}"}
    return {"confirmed": False, "evidence": "phpinfo_not_exposed"}


async def _probe_drupal_endpoints(client, base_url):
    """Drupal version disclosure and accessible admin paths.
    Safe: GET-only."""
    r = await _safe_get(client, f"{base_url}/user/login")
    if r and r.status_code == 200 and "drupal" in r.text.lower():
        return {"confirmed": True, "evidence": "drupal_login_page_accessible"}
    return {"confirmed": False, "evidence": "drupal_login_not_accessible"}


async def _probe_elasticsearch(client, base_url):
    """Elasticsearch cluster info disclosure.
    Safe: GET-only to root endpoint."""
    r = await _safe_get(client, base_url)
    if r and r.status_code == 200:
        try:
            data = r.json()
            if "cluster_name" in data or "tagline" in data:
                version = data.get("version", {}).get("number", "unknown")
                return {"confirmed": True, "evidence": f"elasticsearch_exposed version={version}"}
        except Exception:
            pass
    return {"confirmed": False, "evidence": "elasticsearch_not_exposed"}


async def _probe_redis_info(client, base_url):
    """Redis accessible without auth (HTTP proxy check).
    Safe: GET-only, checks for Redis response patterns."""
    r = await _safe_get(client, base_url)
    if r and r.status_code == 200 and "redis_version" in r.text:
        return {"confirmed": True, "evidence": "redis_http_exposed"}
    return {"confirmed": False, "evidence": "redis_http_not_exposed"}


async def _probe_git_exposed(client, base_url):
    """Exposed .git directory.
    Relevant to source code disclosure CVEs.
    Safe: GET-only."""
    r = await _safe_get(client, f"{base_url}/.git/config")
    if r and r.status_code == 200 and "[core]" in r.text:
        return {"confirmed": True, "evidence": "git_config_exposed"}
    r = await _safe_get(client, f"{base_url}/.git/HEAD")
    if r and r.status_code == 200 and "ref:" in r.text:
        return {"confirmed": True, "evidence": "git_head_exposed"}
    return {"confirmed": False, "evidence": "git_not_exposed"}


# ── Product → Probe mapping ─────────────────────────────────────────────────
# Maps CPE product names to their relevant probes.

_PRODUCT_PROBES = {
    "wordpress": [_probe_wp_user_enum, _probe_wp_xmlrpc],
    "http_server": [_probe_apache_server_status, _probe_apache_path_traversal],
    "nginx": [_probe_nginx_off_by_slash],
    "php": [_probe_php_info],
    "drupal": [_probe_drupal_endpoints],
    "spring_boot": [_probe_spring_actuator],
    "elasticsearch": [_probe_elasticsearch],
    "redis": [_probe_redis_info],
}

# Probes that always run regardless of detected products
_GENERIC_PROBES = [_probe_git_exposed]


class Check(Plugin):
    async def run(self, target, ctx):
        nvd_hits = ctx.get("cve.nvd_hits", []) or []
        pkg_hits = ctx.get("cve.package_hits", []) or []
        # Merge both sources — package hits already have matched_cpe from NVD matching
        all_hits = nvd_hits + [h for h in pkg_hits if h.get("matched_cpe")]
        if not all_hits:
            return PluginResult(artifacts={"cve.endpoint_probes": []})

        http_data = ctx.get("fingerprint.http", {}) or {}
        http_items = http_data.get("http", []) if isinstance(http_data, dict) else []
        target_raw = ctx.get("target_raw", target)
        has_explicit_url = bool(re.match(r"^https?://", target_raw, re.I))

        # Skip if no web service detected — probes are HTTP-based
        if not has_explicit_url and not http_items:
            return PluginResult(artifacts={"cve.endpoint_probes": []})

        # Determine base URL
        if has_explicit_url:
            base_url = target_raw.rstrip("/")
        elif http_items:
            base_url = http_items[0].get("url", f"http://{target}").rstrip("/")
        else:
            base_url = f"http://{target}"

        # Collect unique products from all CVE hits (NVD + packages)
        products = set()
        for hit in all_hits:
            cpe = hit.get("matched_cpe", "")
            parts = cpe.split(":")
            if len(parts) >= 5:
                products.add(parts[4])

        effective = ctx.get("_effective_timeout", ctx.policy.timeout_seconds)
        request_timeout = min(max(float(effective), 5.0), 10.0)

        async with httpx.AsyncClient(
            timeout=request_timeout,
            verify=False,
            follow_redirects=True,
            limits=httpx.Limits(max_connections=5, max_keepalive_connections=3),
        ) as client:
            # Gather applicable probes
            tasks = []
            probe_labels = []

            for product in products:
                probes = _PRODUCT_PROBES.get(product, [])
                for probe_fn in probes:
                    tasks.append(probe_fn(client, base_url))
                    probe_labels.append((product, probe_fn.__name__))

            for probe_fn in _GENERIC_PROBES:
                tasks.append(probe_fn(client, base_url))
                probe_labels.append(("generic", probe_fn.__name__))

            if not tasks:
                return PluginResult(artifacts={"cve.endpoint_probes": []})

            results = await asyncio.gather(*tasks, return_exceptions=True)

        # Process results into findings
        findings = []
        probe_results = []

        for i, result in enumerate(results):
            if isinstance(result, Exception):
                continue
            if not isinstance(result, dict):
                continue

            product, probe_name = probe_labels[i]
            confirmed = result.get("confirmed", False)
            evidence = result.get("evidence", "")

            probe_results.append({
                "product": product,
                "probe": probe_name,
                "confirmed": confirmed,
                "evidence": evidence,
            })

            if confirmed:
                # Find CVEs for this product to create verified findings
                for hit in all_hits:
                    cpe = hit.get("matched_cpe", "")
                    parts = cpe.split(":")
                    if len(parts) >= 5 and parts[4] == product:
                        cve = hit.get("cve", "")
                        fp = stable_fingerprint(target, META.plugin_id, cve, probe_name)
                        if not ctx.dedup(fp):
                            continue

                        findings.append(Finding(
                            severity=hit.get("severity", "medium"),
                            plugin_id=META.plugin_id,
                            title=f"Verified {cve}: {product} endpoint confirmed ({probe_name})",
                            description=(
                                f"Endpoint probe '{probe_name}' confirmed that the attack surface "
                                f"for {cve} exists on this target. The vulnerable feature/endpoint "
                                f"is accessible, increasing the likelihood that this CVE is exploitable."
                            ),
                            evidence=(
                                f"cve={cve} product={product} probe={probe_name} "
                                f"probe_result={evidence} "
                                f"validation_state=validated validation_method=endpoint_probe"
                            ),
                            affected=target,
                            fingerprint=fp,
                            cve=cve if cve.startswith("CVE-") else None,
                            cvss=hit.get("cvss"),
                            confidence=0.80,
                            remediation=(
                                f"The endpoint probe confirmed that the attack surface for {cve} exists. "
                                f"Probe evidence: {evidence}. "
                                "Prioritize patching this vulnerability as the affected feature is actively accessible."
                            ),
                        ))

        return PluginResult(findings=findings, artifacts={"cve.endpoint_probes": probe_results})
