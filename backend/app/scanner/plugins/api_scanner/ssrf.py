"""
API SSRF (Server-Side Request Forgery) Scanner
Tests URL-accepting parameters for:
- Cloud metadata access (AWS/GCP/Azure)
- Internal service probing
- Redirect-based SSRF bypass
"""
import asyncio
import json
import logging
import re
import urllib.parse

from app.scanner.plugins.base import Finding
from app.scanner.context import stable_fingerprint

logger = logging.getLogger("vulnscan.api_scanner.ssrf")

_METADATA_URLS = [
    ("http://169.254.169.254/latest/meta-data/", "AWS", ["ami-id", "instance-id", "hostname"]),
    ("http://169.254.169.254/latest/meta-data/iam/security-credentials/", "AWS IAM", ["AccessKeyId", "SecretAccessKey"]),
    ("http://metadata.google.internal/computeMetadata/v1/", "GCP", ["project-id", "attributes"]),
    ("http://169.254.169.254/metadata/instance?api-version=2021-02-01", "Azure", ["compute", "vmId"]),
    ("http://127.0.0.1/", "Localhost", ["<html", "<body"]),
    ("http://127.0.0.1:8080/", "Localhost:8080", ["<html", "api"]),
    ("http://[::1]/", "IPv6", ["<html"]),
]

_SSRF_PARAMS = ["url", "uri", "src", "source", "href", "link", "fetch", "proxy",
                "callback", "redirect", "image", "img", "file", "load", "page",
                "feed", "pdf", "doc", "data", "webhook", "api_url", "endpoint"]

_BYPASS_PAYLOADS = [
    ("http://0177.0.0.1/", "octal_ip"),
    ("http://0x7f000001/", "hex_ip"),
    ("http://2130706433/", "decimal_ip"),
    ("http://127.1/", "short_ip"),
    ("http://localhost/", "localhost"),
    ("http://spoofed.burpcollaborator.net/", "dns_rebind"),
]


async def check(client, endpoints, ctx) -> list[Finding]:
    findings = []
    target = ctx.get("target_raw", "unknown")

    for ep in endpoints[:15]:
        # Find URL-accepting parameters
        url_params = [p for p in ep.parameters if p.name.lower() in _SSRF_PARAMS]
        if not url_params:
            # Check all params if none match by name
            url_params = [p for p in ep.parameters if p.location in ("query", "body")][:2]

        # Get baseline to filter indicators already in the normal response
        bl = await client.baseline_request(ep)
        bl_body_lower = bl.body.lower() if bl.status > 0 else ""

        for param in url_params[:3]:
            for meta_url, cloud, indicators in _METADATA_URLS[:5]:
                # GET param injection
                r = await client.send_payload(ep, param.name, meta_url, param.location)
                if r.status not in (200, 201):
                    continue

                # Only count indicators absent from the baseline to
                # prevent false positives from pages with cloud terms
                matched = [
                    ind for ind in indicators
                    if ind.lower() in r.body.lower()
                    and ind.lower() not in bl_body_lower
                ]
                if matched:
                    sev = "critical" if "AccessKeyId" in matched or "SecretAccessKey" in matched else "high"
                    fp = stable_fingerprint(target, "api.scanner.ssrf", cloud, ep.path, param.name)
                    findings.append(Finding(
                        severity=sev, plugin_id="api.scanner.ssrf",
                        title=f"SSRF to {cloud}: {ep.method} {ep.path} [{param.name}]",
                        description=(
                            f"SSRF confirmed. Parameter '{param.name}' fetched {cloud} metadata. "
                            f"Indicators found: {matched}."
                            + (" IAM credentials exposed — full cloud compromise possible!" if sev == "critical" else "")
                        ),
                        evidence=f"path={ep.path} param={param.name} cloud={cloud} meta_url={meta_url} indicators={matched}",
                        affected=target, fingerprint=fp, confidence=0.95,
                        cvss=9.8 if sev == "critical" else 8.6,
                        remediation=(
                            f"[{sev.upper()} — CWE-918 / OWASP API7:2023]\n\n"
                            f"[FIX]\n"
                            f"1. Block requests to 169.254.169.254 and internal IPs\n"
                            f"2. Use URL allowlisting — only allow known external domains\n"
                            f"3. Enable IMDSv2 on AWS: aws ec2 modify-instance-metadata-options --http-tokens required\n"
                            f"4. Resolve DNS before fetching to check for internal IPs"
                        ),
                        references=["https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html"],
                    ))
                    break

            if any(f for f in findings if param.name in (f.evidence or "")):
                break

            # Bypass payloads
            for bypass_url, desc in _BYPASS_PAYLOADS[:3]:
                r = await client.send_payload(ep, param.name, bypass_url, param.location)
                if r.status in (200, 201) and r.body_length > 100:
                    if any(ind.lower() in r.body.lower() for ind in ["<html", "<body", "api", "json"]):
                        fp = stable_fingerprint(target, "api.scanner.ssrf", "bypass", ep.path, param.name)
                        findings.append(Finding(
                            severity="high", plugin_id="api.scanner.ssrf",
                            title=f"SSRF (bypass): {ep.method} {ep.path} [{param.name}] — {desc}",
                            description=f"SSRF via IP bypass technique '{desc}' reached an internal service.",
                            evidence=f"path={ep.path} param={param.name} bypass={desc} bypass_url={bypass_url}",
                            affected=target, fingerprint=fp, confidence=0.80, cvss=8.6,
                            remediation="[HIGH — CWE-918] Block all internal IPs including octal/hex/decimal representations.",
                        ))
                        break

    return findings
