"""
SSL Certificate Transparency Scanner
Queries Certificate Transparency logs to discover subdomains and certificates
for the target domain. Detects expiring/expired certs and wildcard usage.
"""
import asyncio
import json
import re
import ssl
import urllib.parse
import urllib.request

from app.scanner.plugins.base import Plugin, PluginMeta, PluginResult, Finding
from app.scanner.context import stable_fingerprint

META = PluginMeta(
    plugin_id="recon.ssl.ct",
    name="SSL Certificate Transparency",
    category="recon",
    depends_on=["net.port.discovery.v2"],
    consumes=["net.open_ports"],
    provides=["recon.ct_domains"],
    enabled_by_default=True,
    timeout_seconds=30.0,
)

# crt.sh API — free Certificate Transparency log search
_CRTSH_API = "https://crt.sh/?q={domain}&output=json"


def _extract_domain(target_raw: str, target: str) -> str:
    """Extract base domain from target."""
    if re.match(r"^https?://", target_raw, re.I):
        parsed = urllib.parse.urlparse(target_raw)
        host = parsed.hostname or target
    else:
        host = target

    # Strip port
    host = host.split(":")[0]

    # If IP, return as-is (CT won't work but we handle gracefully)
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", host):
        return ""

    # Extract base domain (e.g., sub.example.com → example.com)
    parts = host.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host


class Check(Plugin):
    async def run(self, target: str, ctx) -> PluginResult:
        target_raw = ctx.get("target_raw", target)
        findings = []
        ct_domains = []

        domain = _extract_domain(target_raw, target)
        if not domain:
            return PluginResult(artifacts={"recon.ct_domains": []})

        # Query crt.sh for certificates
        try:
            url = _CRTSH_API.format(domain=urllib.parse.quote(f"%.{domain}"))
            req = urllib.request.Request(url, headers={
                "User-Agent": "VulnScan/2.1",
                "Accept": "application/json",
            })

            def _fetch():
                ctx_ssl = ssl.create_default_context()
                with urllib.request.urlopen(req, timeout=20, context=ctx_ssl) as resp:
                    return json.loads(resp.read().decode())

            data = await asyncio.to_thread(_fetch)
        except Exception as e:
            findings.append(Finding(
                severity="info",
                plugin_id=META.plugin_id,
                title=f"CT log query failed for {domain}",
                evidence=f"error={str(e)[:200]}",
                affected=target,
                fingerprint=stable_fingerprint(target, META.plugin_id, "error"),
                remediation="Certificate Transparency log query failed. This may be due to network restrictions or rate limiting.",
            ))
            return PluginResult(findings=findings, artifacts={"recon.ct_domains": []})

        if not data:
            return PluginResult(artifacts={"recon.ct_domains": []})

        # Extract unique subdomains
        seen_domains = set()
        certs = []
        for entry in data:
            name = entry.get("common_name", "")
            san = entry.get("name_value", "")
            issuer = entry.get("issuer_name", "")
            not_after = entry.get("not_after", "")

            # Collect all domain names
            for d in [name] + san.split("\n"):
                d = d.strip().lower().lstrip("*.")
                if d and d.endswith(domain) and d not in seen_domains:
                    seen_domains.add(d)
                    ct_domains.append(d)

            cert_id = entry.get("id", "")
            if cert_id and cert_id not in [c.get("id") for c in certs]:
                certs.append({
                    "id": cert_id,
                    "common_name": name,
                    "san": san,
                    "issuer": issuer,
                    "not_after": not_after,
                })

        # Finding: subdomains discovered
        if ct_domains:
            fp = stable_fingerprint(target, META.plugin_id, "subdomains", str(len(ct_domains)))
            findings.append(Finding(
                severity="info",
                plugin_id=META.plugin_id,
                title=f"CT logs reveal {len(ct_domains)} subdomain(s) for {domain}",
                description=(
                    f"Certificate Transparency logs contain {len(ct_domains)} unique subdomains "
                    f"for {domain}. These subdomains may expose additional attack surface."
                ),
                evidence=f"domain={domain} subdomains={sorted(ct_domains)[:30]} total={len(ct_domains)}",
                affected=target,
                fingerprint=fp,
                confidence=1.0,
                remediation=(
                    f"[INFO] {len(ct_domains)} subdomains discovered via CT logs\n\n"
                    f"[ACTION]\n"
                    f"1. Review all discovered subdomains for unauthorized services\n"
                    f"2. Check for dangling DNS records (subdomain takeover risk)\n"
                    f"3. Ensure all subdomains have valid, non-expired certificates\n\n"
                    f"[SUBDOMAINS]\n" + "\n".join(f"  - {d}" for d in sorted(ct_domains)[:20])
                ),
                references=["https://certificate.transparency.dev/"],
            ))

        # Check for wildcard certificates
        wildcards = [e for e in data if "*" in (e.get("common_name", "") + e.get("name_value", ""))]
        if wildcards:
            fp = stable_fingerprint(target, META.plugin_id, "wildcard")
            findings.append(Finding(
                severity="low",
                plugin_id=META.plugin_id,
                title=f"Wildcard certificate in use for *.{domain}",
                description=(
                    f"A wildcard certificate (*.{domain}) was found in CT logs. "
                    f"Wildcard certs can mask unauthorized subdomains since any subdomain "
                    f"will have a valid certificate."
                ),
                evidence=f"domain=*.{domain} wildcard_certs={len(wildcards)}",
                affected=target,
                fingerprint=fp,
                confidence=0.90,
                remediation=(
                    f"[AFFECTED] Wildcard certificate: *.{domain}\n\n"
                    f"[RISK] Wildcard certs allow any subdomain to have valid TLS, "
                    f"making it harder to detect unauthorized subdomains.\n\n"
                    f"[RECOMMENDATION]\n"
                    f"- Use specific certificates per subdomain where possible\n"
                    f"- Monitor CT logs for unexpected certificate issuance\n"
                    f"- Set up CAA DNS records to restrict certificate authorities"
                ),
                references=["https://letsencrypt.org/docs/caa/"],
            ))

        # Check for expired certificates
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc)
        for cert in certs[:50]:
            not_after = cert.get("not_after", "")
            if not not_after:
                continue
            try:
                expiry = datetime.strptime(not_after, "%Y-%m-%dT%H:%M:%S")
                expiry = expiry.replace(tzinfo=timezone.utc)
                if expiry < now:
                    cn = cert.get("common_name", "unknown")
                    fp = stable_fingerprint(target, META.plugin_id, "expired", cn)
                    findings.append(Finding(
                        severity="medium",
                        plugin_id=META.plugin_id,
                        title=f"Expired certificate found: {cn}",
                        description=f"Certificate for {cn} expired on {not_after}.",
                        evidence=f"cn={cn} expired={not_after} issuer={cert.get('issuer', '')}",
                        affected=target,
                        fingerprint=fp,
                        confidence=0.85,
                        remediation=f"Renew the certificate for {cn}. Consider using Let's Encrypt with auto-renewal.",
                        references=["https://letsencrypt.org/"],
                    ))
                    break  # Report only first expired cert
            except Exception:
                continue

        return PluginResult(
            findings=findings,
            artifacts={"recon.ct_domains": ct_domains},
        )
