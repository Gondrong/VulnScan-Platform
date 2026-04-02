"""
Deep Technology Fingerprinting — technology-specific version detection
that goes beyond regex on Server headers and HTML source.

Probes known endpoints, default files, and API routes to extract exact
version information with high confidence.

Safety: All probes are GET-only and read-only. No modifications are made
to the target system.
"""
import asyncio
import re

import httpx

from app.scanner.plugins.base import Finding, Plugin, PluginMeta, PluginResult
from app.scanner.context import stable_fingerprint

META = PluginMeta(
    plugin_id="fingerprint.deep",
    name="Deep Technology Fingerprinting",
    category="fingerprint",
    depends_on=["fingerprint.http", "fingerprint.web.tech"],
    consumes=["fingerprint.http", "fingerprint.webtech"],
    provides=["fingerprint.deep"],
    enabled_by_default=True,
    timeout_seconds=20.0,
)


async def _safe_get(client, url, **kwargs):
    try:
        return await client.get(url, **kwargs)
    except Exception:
        return None


# ── Probe functions ──────────────────────────────────────────────────────────
# Each returns a list of dicts: {"name", "version", "confidence", "source", "type"}

async def _probe_wordpress(client, base_url):
    results = []

    # WP REST API — often exposes WP version
    r = await _safe_get(client, f"{base_url}/wp-json/")
    if r and r.status_code == 200:
        try:
            data = r.json()
            # WP REST API root often has namespace info
            if "namespaces" in data or "name" in data:
                # Version may be in the generator or via wp-json/wp/v2
                results.append({
                    "name": "wordpress", "version": None,
                    "confidence": 0.90, "source": "wp_rest_api", "type": "cms",
                })
        except Exception:
            pass

    # RSS feed — generator meta tag with version
    r = await _safe_get(client, f"{base_url}/feed/")
    if r and r.status_code == 200:
        m = re.search(r'<generator>.*?wordpress.*?v=([0-9.]+)', r.text, re.I)
        if m:
            results.append({
                "name": "wordpress", "version": m.group(1),
                "confidence": 0.95, "source": "rss_generator", "type": "cms",
            })

    # wp-login.php — version in CSS/JS query params
    r = await _safe_get(client, f"{base_url}/wp-login.php")
    if r and r.status_code == 200:
        m = re.search(r'ver=([0-9]+\.[0-9]+(?:\.[0-9]+)?)', r.text)
        if m:
            results.append({
                "name": "wordpress", "version": m.group(1),
                "confidence": 0.90, "source": "wp_login_ver", "type": "cms",
            })

    return results


async def _probe_drupal(client, base_url):
    results = []

    for path in ["/CHANGELOG.txt", "/core/CHANGELOG.txt"]:
        r = await _safe_get(client, f"{base_url}{path}")
        if r and r.status_code == 200:
            m = re.search(r'Drupal\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)', r.text[:500])
            if m:
                results.append({
                    "name": "drupal", "version": m.group(1),
                    "confidence": 0.95, "source": "changelog", "type": "cms",
                })
                break

    # Drupal meta generator
    r = await _safe_get(client, base_url)
    if r and r.status_code == 200:
        m = re.search(r'<meta\s+name="generator"\s+content="Drupal\s+([0-9.]+)', r.text, re.I)
        if m:
            results.append({
                "name": "drupal", "version": m.group(1),
                "confidence": 0.90, "source": "meta_generator", "type": "cms",
            })

    return results


async def _probe_joomla(client, base_url):
    results = []

    r = await _safe_get(client, f"{base_url}/administrator/manifests/files/joomla.xml")
    if r and r.status_code == 200:
        m = re.search(r'<version>([0-9]+\.[0-9]+(?:\.[0-9]+)?)</version>', r.text, re.I)
        if m:
            results.append({
                "name": "joomla", "version": m.group(1),
                "confidence": 0.95, "source": "manifest_xml", "type": "cms",
            })

    return results


async def _probe_error_page_version(client, base_url):
    """Extract server version from default 404 error pages."""
    results = []
    r = await _safe_get(client, f"{base_url}/vulnscan_nonexistent_path_probe_404")
    if r and r.status_code in (404, 403):
        body = r.text[-500:] if len(r.text) > 500 else r.text

        # Apache error page footer: "Apache/2.4.41 (Ubuntu) Server at ..."
        m = re.search(r'Apache/([0-9]+\.[0-9]+\.[0-9]+)', body, re.I)
        if m:
            results.append({
                "name": "apache", "version": m.group(1),
                "confidence": 0.95, "source": "error_page", "type": "server",
            })

        # nginx error page: "nginx/1.18.0"
        m = re.search(r'nginx/([0-9]+\.[0-9]+\.[0-9]+)', body, re.I)
        if m:
            results.append({
                "name": "nginx", "version": m.group(1),
                "confidence": 0.95, "source": "error_page", "type": "server",
            })

        # Microsoft IIS
        m = re.search(r'Microsoft-IIS/([0-9]+\.[0-9]+)', body, re.I)
        if m:
            results.append({
                "name": "iis", "version": m.group(1),
                "confidence": 0.90, "source": "error_page", "type": "server",
            })

    return results


async def _probe_spring_boot(client, base_url):
    """Check for exposed Spring Boot Actuator endpoints."""
    results = []

    for path in ["/actuator", "/actuator/info", "/actuator/health"]:
        r = await _safe_get(client, f"{base_url}{path}")
        if r and r.status_code == 200:
            try:
                data = r.json()
                if isinstance(data, dict) and ("status" in data or "_links" in data or "build" in data):
                    version = None
                    build = data.get("build", {})
                    if isinstance(build, dict):
                        version = build.get("version")
                    results.append({
                        "name": "spring_boot", "version": version,
                        "confidence": 0.95, "source": "actuator", "type": "framework",
                    })
                    break
            except Exception:
                pass

    return results


async def _probe_php_version(client, base_url):
    """Detect PHP version from exposed phpinfo or headers."""
    results = []

    # Check phpinfo.php
    r = await _safe_get(client, f"{base_url}/phpinfo.php")
    if r and r.status_code == 200 and "PHP Version" in r.text:
        m = re.search(r'PHP Version\s*</td><td[^>]*>([0-9]+\.[0-9]+\.[0-9]+)', r.text)
        if m:
            results.append({
                "name": "php", "version": m.group(1),
                "confidence": 0.95, "source": "phpinfo", "type": "runtime",
            })

    # Check X-Powered-By variants
    r = await _safe_get(client, base_url)
    if r:
        for hdr in ["x-powered-by", "server"]:
            val = r.headers.get(hdr, "")
            m = re.search(r'PHP/([0-9]+\.[0-9]+(?:\.[0-9]+)?)', val, re.I)
            if m:
                results.append({
                    "name": "php", "version": m.group(1),
                    "confidence": 0.90, "source": "header", "type": "runtime",
                })
                break

    return results


async def _probe_nextjs(client, base_url):
    """Detect Next.js via /_next/data or build manifest."""
    results = []

    r = await _safe_get(client, f"{base_url}/_next/static/chunks/webpack.js")
    if r and r.status_code == 200:
        results.append({
            "name": "nextjs", "version": None,
            "confidence": 0.85, "source": "webpack_chunk", "type": "framework",
        })

    # __NEXT_DATA__ in main page
    r = await _safe_get(client, base_url)
    if r and r.status_code == 200 and "__NEXT_DATA__" in r.text:
        m = re.search(r'"nextRuntime"\s*:\s*"([^"]+)"', r.text)
        results.append({
            "name": "nextjs", "version": None,
            "confidence": 0.90, "source": "next_data", "type": "framework",
        })

    return results


# ── Probe registry ───────────────────────────────────────────────────────────
# Maps detected technology names → probe functions.
# Each probe is called only if the relevant technology was detected by web_tech.

async def _probe_iis_aspnet(client, base_url):
    """Detect IIS/ASP.NET version from response headers and error pages."""
    results = []

    # Check default page and error pages for IIS/ASP.NET headers
    for path in ["", "/doesnotexist.aspx", "/doesnotexist.asp"]:
        r = await _safe_get(client, f"{base_url}/{path.lstrip('/')}" if path else base_url)
        if not r:
            continue

        # X-AspNet-Version header
        aspnet_ver = r.headers.get("x-aspnet-version", "")
        if aspnet_ver:
            results.append({
                "name": "asp.net", "version": aspnet_ver,
                "confidence": 0.95, "source": "header:x-aspnet-version", "type": "framework",
            })

        # X-AspNetMvc-Version header
        mvc_ver = r.headers.get("x-aspnetmvc-version", "")
        if mvc_ver:
            results.append({
                "name": "asp.net", "version": mvc_ver,
                "confidence": 0.90, "source": "header:x-aspnetmvc-version", "type": "framework",
            })

        # X-Powered-By: ASP.NET
        powered = r.headers.get("x-powered-by", "")
        if "asp.net" in powered.lower():
            results.append({
                "name": "asp.net", "version": None,
                "confidence": 0.85, "source": "header:x-powered-by", "type": "framework",
            })

        # IIS version from Server header
        server = r.headers.get("server", "")
        m = re.search(r'Microsoft-IIS/([0-9]+\.?[0-9]*)', server, re.I)
        if m:
            results.append({
                "name": "iis", "version": m.group(1),
                "confidence": 0.95, "source": "header:server", "type": "server",
            })

        # IIS detailed error pages reveal version
        if r.status_code in (404, 500, 403) and r.text:
            body = r.text[:4000]
            m = re.search(r'IIS[/ ]([0-9]+\.?[0-9]*)', body, re.I)
            if m:
                results.append({
                    "name": "iis", "version": m.group(1),
                    "confidence": 0.90, "source": "error_page", "type": "server",
                })
            # ASP.NET detailed error
            if "ASP.NET" in body or "System.Web" in body or "__VIEWSTATE" in body:
                m = re.search(r'Version[: ]+([0-9]+\.[0-9]+\.[0-9]+)', body)
                if m:
                    results.append({
                        "name": "asp.net", "version": m.group(1),
                        "confidence": 0.85, "source": "error_page", "type": "framework",
                    })

        if results:
            break

    return results


async def _probe_tomcat(client, base_url):
    """Detect Apache Tomcat from default pages and error responses."""
    results = []

    # Default Tomcat manager/status pages
    for path in ["/manager/html", "/status", "/docs/"]:
        r = await _safe_get(client, f"{base_url}{path}")
        if r and r.text:
            m = re.search(r'Apache Tomcat[/ ]*([0-9]+\.[0-9]+(?:\.[0-9]+)?)', r.text, re.I)
            if m:
                results.append({
                    "name": "tomcat", "version": m.group(1),
                    "confidence": 0.95, "source": f"page:{path}", "type": "server",
                })
                break

    # Check error page for Tomcat default styling
    if not results:
        r = await _safe_get(client, f"{base_url}/vulnscan_probe_404")
        if r and r.text:
            m = re.search(r'Apache Tomcat[/ ]*([0-9]+\.[0-9]+(?:\.[0-9]+)?)', r.text, re.I)
            if m:
                results.append({
                    "name": "tomcat", "version": m.group(1),
                    "confidence": 0.90, "source": "error_page", "type": "server",
                })

    return results


_ALWAYS_RUN_PROBES = [
    _probe_error_page_version,
    _probe_php_version,
    _probe_iis_aspnet,
]

_TECH_PROBES = {
    "wordpress": _probe_wordpress,
    "drupal": _probe_drupal,
    "joomla": _probe_joomla,
    "spring": _probe_spring_boot,
    "spring_boot": _probe_spring_boot,
    "next.js": _probe_nextjs,
    "nextjs": _probe_nextjs,
    "iis": _probe_iis_aspnet,
    "asp.net": _probe_iis_aspnet,
    "tomcat": _probe_tomcat,
    "apache_tomcat": _probe_tomcat,
}


class Check(Plugin):
    async def run(self, target, ctx):
        http_data = ctx.get("fingerprint.http", {}) or {}
        http_items = http_data.get("http", []) if isinstance(http_data, dict) else []
        webtech = ctx.get("fingerprint.webtech", []) or []
        target_raw = ctx.get("target_raw", target)
        has_explicit_url = bool(re.match(r"^https?://", target_raw, re.I))

        # Skip if no web service detected — deep fingerprinting is HTTP-based
        if not has_explicit_url and not http_items:
            return PluginResult(artifacts={"fingerprint.deep": []})

        # Determine base URL
        if has_explicit_url:
            base_url = target_raw.rstrip("/")
        elif http_items:
            base_url = http_items[0].get("url", f"http://{target}").rstrip("/")
        else:
            base_url = f"http://{target}"

        # Collect detected tech names
        detected_tech = set()
        for t in webtech:
            name = (t.get("name") or "").lower()
            if name:
                detected_tech.add(name)

        effective = ctx.get("_effective_timeout", ctx.policy.timeout_seconds)
        request_timeout = min(max(float(effective), 5.0), 10.0)

        all_results = []
        async with httpx.AsyncClient(
            timeout=request_timeout,
            verify=False,
            follow_redirects=True,
            limits=httpx.Limits(max_connections=5, max_keepalive_connections=3),
        ) as client:
            # Always-run probes
            tasks = [probe(client, base_url) for probe in _ALWAYS_RUN_PROBES]

            # Tech-specific probes
            for tech_name, probe_fn in _TECH_PROBES.items():
                if tech_name in detected_tech:
                    tasks.append(probe_fn(client, base_url))

            # If no specific tech detected, try CMS probes speculatively
            if not detected_tech & set(_TECH_PROBES.keys()):
                tasks.append(_probe_wordpress(client, base_url))
                tasks.append(_probe_spring_boot(client, base_url))

            results = await asyncio.gather(*tasks, return_exceptions=True)
            for r in results:
                if isinstance(r, list):
                    all_results.extend(r)

        # Deduplicate: keep highest-confidence per (name, version)
        best = {}
        for item in all_results:
            key = (item["name"], item.get("version"))
            if key not in best or item["confidence"] > best[key]["confidence"]:
                best[key] = item

        deduped = list(best.values())

        # Generate info-level findings for discoveries
        findings = []
        for item in deduped:
            version_str = item.get("version") or "unknown version"
            fp = stable_fingerprint(target, META.plugin_id, item["name"], version_str)
            if not ctx.dedup(fp):
                continue
            findings.append(Finding(
                severity="info",
                plugin_id=META.plugin_id,
                title=f"Deep fingerprint: {item['name']} {version_str} (via {item['source']})",
                description=(
                    f"Detected {item['name']} version {version_str} through "
                    f"technology-specific probing ({item['source']}). "
                    f"Confidence: {item['confidence']:.0%}."
                ),
                evidence=(
                    f"tech={item['name']} version={version_str} "
                    f"source={item['source']} type={item['type']} "
                    f"confidence={item['confidence']}"
                ),
                affected=target,
                fingerprint=fp,
                confidence=item["confidence"],
            ))

        return PluginResult(findings=findings, artifacts={"fingerprint.deep": deduped})

