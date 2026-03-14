"""
DNS Enumeration Plugin — discovers subdomains, checks zone transfers,
and enumerates DNS records for the target domain.

Provides target discovery for the scan pipeline by finding additional
hostnames and IPs associated with the target domain.

No external dependencies — uses the system's DNS resolver via asyncio.
"""
import asyncio
import logging
import socket
import struct
import time

from app.scanner.plugins.base import Finding, Plugin, PluginMeta, PluginResult
from app.scanner.context import stable_fingerprint

logger = logging.getLogger("vulnscan.dns_enum")

META = PluginMeta(
    plugin_id="recon.dns.enum",
    name="DNS Enumeration",
    category="network",
    depends_on=["net.port.discovery.v2"],
    consumes=["net.open_ports"],
    provides=["recon.dns.records", "recon.dns.subdomains"],
    enabled_by_default=True,
    timeout_seconds=30.0,
)

# Common subdomain prefixes to brute-force
_SUBDOMAIN_WORDLIST = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "webmail",
    "ns1", "ns2", "ns3", "dns", "dns1", "dns2",
    "admin", "portal", "vpn", "remote", "gateway",
    "dev", "staging", "stage", "test", "testing", "qa", "uat",
    "api", "api2", "api-v2", "rest", "graphql",
    "app", "webapp", "web", "mobile",
    "cdn", "static", "assets", "media", "img", "images",
    "db", "database", "mysql", "postgres", "redis", "mongo",
    "git", "gitlab", "github", "bitbucket", "svn",
    "ci", "jenkins", "build", "deploy", "docker", "registry",
    "monitor", "monitoring", "grafana", "prometheus", "kibana",
    "logs", "syslog", "elk", "elastic", "elasticsearch",
    "backup", "bak", "old", "legacy", "archive",
    "internal", "intranet", "extranet", "private",
    "sso", "auth", "login", "id", "identity", "oauth",
    "cms", "blog", "wiki", "docs", "help", "support",
    "shop", "store", "pay", "payment", "billing",
    "mx", "mx1", "mx2", "relay", "exchange",
    "proxy", "lb", "loadbalancer", "ha", "cluster",
    "s3", "storage", "files", "cloud",
    "jira", "confluence", "slack", "teams",
]


def _extract_domain(target: str) -> str | None:
    """Extract the registrable domain from a hostname or IP.
    Returns None if target is an IP address.
    """
    host = target.strip().lower()
    # Skip IP addresses
    try:
        socket.inet_aton(host)
        return None
    except OSError:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, host)
        return None
    except OSError:
        pass

    # Remove trailing dot
    host = host.rstrip(".")

    # If it looks like a bare domain (e.g., example.com), use it directly
    parts = host.split(".")
    if len(parts) < 2:
        return None

    # Return the last two parts as the domain (simplified — no PSL)
    # For subdomains like www.example.com, returns example.com
    if len(parts) > 2:
        return ".".join(parts[-2:])
    return host


async def _resolve_hostname(hostname: str, timeout: float = 3.0) -> list[str]:
    """Resolve a hostname to IP addresses."""
    loop = asyncio.get_event_loop()
    try:
        result = await asyncio.wait_for(
            loop.getaddrinfo(hostname, None, family=socket.AF_INET),
            timeout=timeout,
        )
        return list({addr[4][0] for addr in result})
    except Exception:
        return []


async def _check_zone_transfer(domain: str, ns_host: str, timeout: float = 5.0) -> list[str]:
    """
    Attempt a DNS zone transfer (AXFR) against a nameserver.
    Returns list of discovered hostnames if transfer succeeds.

    Uses raw TCP DNS protocol — no external libraries required.
    """
    discovered = []
    try:
        # Build minimal AXFR query
        # Transaction ID
        txn_id = b"\x13\x37"
        # Flags: standard query
        flags = b"\x00\x00"
        # Questions=1, Answers=0, Authority=0, Additional=0
        counts = b"\x00\x01\x00\x00\x00\x00\x00\x00"
        # Encode domain name
        qname = b""
        for label in domain.split("."):
            qname += bytes([len(label)]) + label.encode("ascii")
        qname += b"\x00"
        # QTYPE=AXFR (252), QCLASS=IN (1)
        question = qname + b"\x00\xfc\x00\x01"

        dns_msg = txn_id + flags + counts + question
        # TCP DNS: 2-byte length prefix
        tcp_msg = struct.pack("!H", len(dns_msg)) + dns_msg

        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ns_host, 53), timeout=timeout
        )
        writer.write(tcp_msg)
        await writer.drain()

        # Read response length
        len_data = await asyncio.wait_for(reader.readexactly(2), timeout=timeout)
        resp_len = struct.unpack("!H", len_data)[0]

        if resp_len > 0 and resp_len < 65535:
            resp_data = await asyncio.wait_for(reader.readexactly(resp_len), timeout=timeout)
            # Check RCODE in response flags
            if len(resp_data) >= 4:
                rcode = resp_data[3] & 0x0F
                if rcode == 0:  # NOERROR — transfer may have succeeded
                    # Parse response for hostnames (simplified)
                    text = resp_data.decode("ascii", errors="ignore")
                    # Look for readable hostname patterns
                    for part in text.split("\x00"):
                        clean = "".join(c for c in part if c.isalnum() or c in ".-")
                        if clean and domain in clean and len(clean) > len(domain) + 1:
                            discovered.append(clean)

        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

    except Exception:
        pass

    return list(set(discovered))


async def _resolve_nameservers(domain: str, timeout: float = 3.0) -> list[str]:
    """Get nameserver hostnames for a domain using system resolver."""
    loop = asyncio.get_event_loop()
    try:
        # Use getaddrinfo to resolve NS records indirectly
        # We'll try to resolve ns1/ns2 patterns as a heuristic
        ns_hosts = []
        for prefix in ["ns1", "ns2", "ns", "dns1", "dns2"]:
            hostname = f"{prefix}.{domain}"
            ips = await _resolve_hostname(hostname, timeout)
            if ips:
                ns_hosts.append(hostname)
        return ns_hosts
    except Exception:
        return []


class Check(Plugin):
    async def run(self, target: str, ctx) -> PluginResult:
        open_ports = ctx.get("net.open_ports", []) or []
        effective = ctx.get("_effective_timeout", 30.0)
        findings: list[Finding] = []
        discovered_subdomains: list[dict] = []
        dns_records: list[dict] = []

        domain = _extract_domain(target)
        if not domain:
            # Target is an IP — limited DNS enum (reverse lookup only)
            try:
                loop = asyncio.get_event_loop()
                result = await asyncio.wait_for(
                    loop.getnameinfo((target, 0), 0),
                    timeout=5.0,
                )
                if result and result[0] and result[0] != target:
                    dns_records.append({
                        "type": "PTR",
                        "name": target,
                        "value": result[0],
                    })
                    findings.append(Finding(
                        severity="info",
                        plugin_id=META.plugin_id,
                        title=f"Reverse DNS: {target} → {result[0]}",
                        evidence=f"ip={target} ptr={result[0]}",
                        affected=target,
                        fingerprint=stable_fingerprint(target, META.plugin_id, "ptr", result[0]),
                    ))
            except Exception:
                pass

            return PluginResult(
                findings=findings,
                artifacts={
                    "recon.dns.records": dns_records,
                    "recon.dns.subdomains": [],
                },
            )

        start_time = time.monotonic()

        # Phase 1: Resolve the main domain
        main_ips = await _resolve_hostname(domain)
        if main_ips:
            dns_records.append({
                "type": "A",
                "name": domain,
                "value": main_ips,
            })

        # Phase 2: Check for zone transfer (if DNS port 53 is open or always try)
        zone_transfer_hosts = []
        ns_hosts = await _resolve_nameservers(domain)

        for ns in ns_hosts[:3]:
            elapsed = time.monotonic() - start_time
            if elapsed > effective * 0.3:
                break
            ns_ips = await _resolve_hostname(ns)
            for ns_ip in ns_ips[:1]:
                zt_results = await _check_zone_transfer(domain, ns_ip)
                if zt_results:
                    zone_transfer_hosts.extend(zt_results)
                    findings.append(Finding(
                        severity="high",
                        plugin_id=META.plugin_id,
                        title=f"DNS zone transfer allowed on {ns}",
                        description=(
                            f"The nameserver {ns} ({ns_ip}) allows AXFR zone transfers. "
                            f"This exposes all DNS records for {domain}, revealing the "
                            f"internal network structure, hostnames, and IP addresses to attackers."
                        ),
                        evidence=(
                            f"nameserver={ns} ip={ns_ip} domain={domain} "
                            f"records_leaked={len(zt_results)} "
                            f"sample={zt_results[:5]}"
                        ),
                        affected=target,
                        fingerprint=stable_fingerprint(target, META.plugin_id, "axfr", ns),
                        remediation=(
                            "[CRITICAL — CIS DNS Benchmark]\n"
                            f"DNS zone transfer is allowed on {ns}. This lets anyone enumerate "
                            f"all records in the {domain} zone.\n\n"
                            "Remediation:\n"
                            "- BIND: Add 'allow-transfer { none; };' to zone configuration\n"
                            "- Windows DNS: Set zone transfer to 'Only to servers listed on the Name Servers tab'\n"
                            "- Route53/Cloudflare: Zone transfers are disabled by default\n\n"
                            "Reference: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover"
                        ),
                        confidence=0.95,
                        references=[
                            "https://cwe.mitre.org/data/definitions/200.html",
                            "https://owasp.org/www-project-web-security-testing-guide/",
                        ],
                    ))

        # Phase 3: Subdomain brute-force
        sem = asyncio.Semaphore(20)
        found_subdomains: list[tuple[str, list[str]]] = []

        async def check_subdomain(prefix: str):
            async with sem:
                hostname = f"{prefix}.{domain}"
                ips = await _resolve_hostname(hostname, timeout=2.0)
                if ips:
                    found_subdomains.append((hostname, ips))

        # Budget: use ~60% of remaining time for subdomain enum
        elapsed = time.monotonic() - start_time
        remaining = effective - elapsed
        budget_for_subs = remaining * 0.6

        # Run in batches to respect budget
        batch_size = 30
        for i in range(0, len(_SUBDOMAIN_WORDLIST), batch_size):
            elapsed = time.monotonic() - start_time
            if elapsed > start_time + budget_for_subs:
                break
            batch = _SUBDOMAIN_WORDLIST[i:i + batch_size]
            await asyncio.gather(
                *[check_subdomain(prefix) for prefix in batch],
                return_exceptions=True,
            )

        # Process discovered subdomains
        for hostname, ips in found_subdomains:
            discovered_subdomains.append({
                "hostname": hostname,
                "ips": ips,
                "source": "brute_force",
            })
            dns_records.append({
                "type": "A",
                "name": hostname,
                "value": ips,
            })

        # Add zone transfer discoveries
        for zt_host in zone_transfer_hosts:
            if not any(s["hostname"] == zt_host for s in discovered_subdomains):
                discovered_subdomains.append({
                    "hostname": zt_host,
                    "ips": [],
                    "source": "zone_transfer",
                })

        # Summary finding
        total_found = len(discovered_subdomains)
        if total_found > 0:
            sub_list = [s["hostname"] for s in discovered_subdomains[:20]]
            findings.append(Finding(
                severity="info",
                plugin_id=META.plugin_id,
                title=f"DNS enumeration: {total_found} subdomains discovered for {domain}",
                description=(
                    f"Subdomain enumeration found {total_found} live hostnames for {domain}. "
                    f"Each discovered subdomain represents a potential additional attack surface."
                ),
                evidence=(
                    f"domain={domain} subdomains_found={total_found} "
                    f"zone_transfer={'yes' if zone_transfer_hosts else 'no'} "
                    f"nameservers={ns_hosts[:3]} "
                    f"discovered={sub_list}"
                ),
                affected=target,
                fingerprint=stable_fingerprint(target, META.plugin_id, "summary", domain),
                remediation=(
                    "Review all discovered subdomains and ensure:\n"
                    "- Each subdomain is intentionally public\n"
                    "- Development/staging subdomains are not exposed\n"
                    "- No subdomain takeover is possible (dangling CNAME records)\n"
                    "- Internal hostnames are not leaking via DNS\n\n"
                    "Consider using DNS monitoring to detect unauthorized subdomain creation."
                ),
            ))

            # Check for potentially sensitive subdomains
            sensitive_prefixes = {
                "admin", "staging", "stage", "dev", "test", "testing", "qa",
                "uat", "internal", "intranet", "private", "backup", "old",
                "legacy", "jenkins", "gitlab", "jira", "confluence", "vpn",
                "db", "database", "mysql", "postgres", "redis", "mongo",
                "docker", "registry", "kibana", "grafana", "prometheus",
                "elasticsearch", "elastic",
            }
            sensitive_found = [
                s["hostname"] for s in discovered_subdomains
                if s["hostname"].split(".")[0] in sensitive_prefixes
            ]
            if sensitive_found:
                findings.append(Finding(
                    severity="medium",
                    plugin_id=META.plugin_id,
                    title=f"Sensitive subdomains exposed: {len(sensitive_found)} found",
                    description=(
                        f"DNS enumeration discovered subdomains that suggest internal "
                        f"infrastructure is exposed to the public internet. "
                        f"These often host admin panels, development environments, or "
                        f"databases that should not be publicly accessible."
                    ),
                    evidence=(
                        f"domain={domain} "
                        f"sensitive_subdomains={sensitive_found[:10]}"
                    ),
                    affected=target,
                    fingerprint=stable_fingerprint(target, META.plugin_id, "sensitive_subs", domain),
                    remediation=(
                        "[OWASP A02:2025 Security Misconfiguration]\n"
                        "Sensitive subdomains should not be publicly resolvable:\n"
                        "- Remove DNS records for internal-only services\n"
                        "- Use split-horizon DNS (internal vs external views)\n"
                        "- Restrict access via firewall rules and VPN\n"
                        "- Ensure dev/staging environments require authentication\n"
                        "- Monitor for subdomain takeover on decommissioned services"
                    ),
                    confidence=0.80,
                    references=[
                        "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
                        "https://cwe.mitre.org/data/definitions/200.html",
                    ],
                ))
        else:
            findings.append(Finding(
                severity="info",
                plugin_id=META.plugin_id,
                title=f"DNS enumeration: no subdomains found for {domain}",
                evidence=(
                    f"domain={domain} checked={len(_SUBDOMAIN_WORDLIST)} "
                    f"zone_transfer={'attempted' if ns_hosts else 'no_ns_found'}"
                ),
                affected=target,
                fingerprint=stable_fingerprint(target, META.plugin_id, "summary", domain),
            ))

        return PluginResult(
            findings=findings,
            artifacts={
                "recon.dns.records": dns_records,
                "recon.dns.subdomains": discovered_subdomains,
            },
        )
