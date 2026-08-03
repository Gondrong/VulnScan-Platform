"""
Favicon Hash Fingerprint — computes MMH3 hash of favicon.ico and matches
against a database of known application hashes (Shodan-style fingerprinting).
"""
import base64
import httpx
import mmh3

from app.scanner.plugins.base import Plugin, PluginMeta, PluginResult, Finding
from app.scanner.context import stable_fingerprint

META = PluginMeta(
    plugin_id="fingerprint.favicon.hash",
    name="Favicon Hash Fingerprint",
    category="fingerprint",
    depends_on=["fingerprint.http"],
    consumes=["fingerprint.http"],
    provides=["fingerprint.favicon"],
    enabled_by_default=True,
    timeout_seconds=6.0,
)

# Known favicon hashes (MMH3 of base64-encoded favicon content).
# Source: Shodan, OWASP favicon database, community contributions.
# Format: hash → (product, severity, description)
_KNOWN_HASHES = {
    # Admin panels & management interfaces
    116323821: ("Jenkins", "medium", "Jenkins CI/CD server detected — admin panel may be exposed"),
    -2057558656: ("Jenkins", "medium", "Jenkins CI/CD server detected"),
    81586820: ("Jira", "info", "Atlassian Jira issue tracker detected"),
    -1299022308: ("Confluence", "info", "Atlassian Confluence wiki detected"),
    -1203021870: ("Grafana", "medium", "Grafana monitoring dashboard detected"),
    1109681256: ("Grafana", "medium", "Grafana monitoring dashboard detected"),
    -1073467747: ("Kibana", "medium", "Kibana log dashboard detected — may expose sensitive log data"),
    1474738628: ("Kibana", "medium", "Kibana log dashboard detected"),
    -316785895: ("phpMyAdmin", "high", "phpMyAdmin detected — database management interface exposed"),
    -428790949: ("phpMyAdmin", "high", "phpMyAdmin detected"),
    -752627830: ("Adminer", "high", "Adminer database management detected"),
    988422585: ("pgAdmin", "high", "pgAdmin PostgreSQL management detected"),
    -223533141: ("Portainer", "high", "Portainer Docker management UI detected"),
    1753867807: ("Portainer", "high", "Portainer Docker management UI detected"),
    862844052: ("Traefik", "medium", "Traefik reverse proxy dashboard detected"),
    # Web servers & frameworks
    -1137684688: ("Apache default", "low", "Apache default page — server may not be configured"),
    -1293290834: ("Apache Tomcat", "medium", "Apache Tomcat default page detected"),
    -297069493: ("Apache Tomcat", "medium", "Apache Tomcat detected"),
    1485257654: ("Nginx default", "low", "Nginx default page — server may not be configured"),
    -1299022308: ("IIS default", "low", "Microsoft IIS default page detected"),
    116323821: ("Jenkins", "medium", "Jenkins CI server detected"),
    # Security & network devices
    359895498: ("FortiGate", "info", "Fortinet FortiGate firewall management interface"),
    -735210072: ("SonicWall", "info", "SonicWall firewall management interface"),
    945408572: ("pfSense", "medium", "pfSense firewall admin panel detected"),
    -1840324437: ("Sophos UTM", "info", "Sophos UTM management interface"),
    442749392: ("Ubiquiti UniFi", "medium", "Ubiquiti UniFi controller detected"),
    # Development & debugging
    -1431561578: ("Spring Boot", "medium", "Spring Boot application detected (may expose actuator endpoints)"),
    -1203021870: ("Prometheus", "medium", "Prometheus metrics server detected — may expose internal metrics"),
    1354567743: ("RabbitMQ", "medium", "RabbitMQ management console detected"),
    823560268: ("Elasticsearch", "medium", "Elasticsearch API detected"),
    -1917313873: ("Solr", "medium", "Apache Solr search platform detected"),
    # CMS
    -1395229403: ("WordPress", "info", "WordPress CMS detected"),
    2087906806: ("WordPress", "info", "WordPress CMS detected"),
    -626322532: ("Drupal", "info", "Drupal CMS detected"),
    1141837924: ("Joomla", "info", "Joomla CMS detected"),
    # Cloud & infrastructure
    -54831658: ("AWS S3", "medium", "AWS S3 bucket listing page detected"),
    1279538595: ("GitLab", "info", "GitLab instance detected"),
    -1032603782: ("Gitea", "info", "Gitea git server detected"),
    116323821: ("Gogs", "info", "Gogs git server detected"),
    # Other
    -1337044534: ("Webmin", "high", "Webmin server administration panel detected"),
    -1649692832: ("cPanel", "medium", "cPanel hosting panel detected"),
    706015695: ("Plesk", "info", "Plesk hosting panel detected"),
    -631337382: ("SonarQube", "medium", "SonarQube code quality platform detected"),
}


class Check(Plugin):
    async def run(self, target, ctx):
        fp = ctx.get("fingerprint.http", {}) or {}
        http_items = fp.get("http", [])
        hashes = []
        findings = []

        for item in http_items:
            url = item.get("url")
            if not url:
                continue
            try:
                async with httpx.AsyncClient(timeout=6, verify=False, follow_redirects=True) as client:
                    r = await client.get(url.rstrip("/") + "/favicon.ico")
                    if r.status_code != 200 or not r.content:
                        continue
                    # Skip common error pages served as favicon (HTML responses)
                    if r.content[:5] in (b"<!DOC", b"<html", b"<HTML", b"<?xml"):
                        continue
                    b64 = base64.b64encode(r.content)
                    h = mmh3.hash(b64)
                    hashes.append({"url": url, "hash": h})

                    # Lookup in known hash database
                    match = _KNOWN_HASHES.get(h)
                    if match:
                        product, severity, description = match
                        fpr = stable_fingerprint(target, META.plugin_id, str(h), product)
                        findings.append(Finding(
                            severity=severity,
                            plugin_id=META.plugin_id,
                            title=f"Favicon identified: {product}",
                            description=f"{description}. Favicon hash: {h}",
                            evidence=f"url={url}/favicon.ico hash={h} product={product}",
                            affected=target,
                            fingerprint=fpr,
                            confidence=0.85,
                            remediation=(
                                f"Application '{product}' was identified via favicon fingerprinting.\n"
                                f"1. Ensure this service is intentionally exposed\n"
                                f"2. Restrict access to management interfaces via IP allowlist or VPN\n"
                                f"3. Replace default favicons to reduce information disclosure"
                            ),
                        ))
            except Exception:
                pass

        return PluginResult(findings=findings, artifacts={"fingerprint.favicon": hashes})
