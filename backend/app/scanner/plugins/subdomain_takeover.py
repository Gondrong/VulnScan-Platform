"""
Subdomain Takeover Detection Plugin
Checks discovered subdomains for dangling CNAME records pointing to unclaimed
third-party services. A successful subdomain takeover allows an attacker to
serve arbitrary content on a legitimate subdomain.

No external tool dependencies — uses socket for DNS and httpx for HTTP checks.
"""
import asyncio
import logging
import re
import socket
import urllib.parse

import httpx

from app.scanner.plugins.base import Finding, Plugin, PluginMeta, PluginResult
from app.scanner.context import stable_fingerprint

logger = logging.getLogger("vulnscan.plugin.subdomain_takeover")

META = PluginMeta(
    plugin_id="recon.subdomain_takeover",
    name="Subdomain Takeover Detection",
    category="recon",
    depends_on=["fingerprint.http"],
    soft_depends_on=["ext.subfinder"],
    consumes=["recon.subdomains", "fingerprint.http"],
    provides=["recon.subdomain_takeover"],
    enabled_by_default=True,
    timeout_seconds=45.0,
)

# Known takeover-vulnerable service fingerprints.
# Each entry: (service_name, cname_pattern, http_fingerprint, severity)
_TAKEOVER_FINGERPRINTS: list[tuple[str, str, str, str]] = [
    (
        "GitHub Pages",
        r"\.github\.io$",
        "There isn't a GitHub Pages site here",
        "high",
    ),
    (
        "Heroku",
        r"\.herokuapp\.com$",
        "No such app",
        "high",
    ),
    (
        "AWS S3",
        r"\.s3[.\-].*\.amazonaws\.com$",
        "NoSuchBucket",
        "high",
    ),
    (
        "AWS S3 (website)",
        r"\.s3-website[.\-].*\.amazonaws\.com$",
        "NoSuchBucket",
        "high",
    ),
    (
        "Shopify",
        r"\.myshopify\.com$",
        "Sorry, this shop is currently unavailable",
        "high",
    ),
    (
        "Tumblr",
        r"\.tumblr\.com$",
        "There's nothing here",
        "high",
    ),
    (
        "Fastly",
        r"\.fastly\.net$",
        "Fastly error: unknown domain",
        "high",
    ),
    (
        "Ghost",
        r"\.ghost\.io$",
        "The thing you were looking for is no longer here",
        "high",
    ),
    (
        "Pantheon",
        r"\.pantheonsite\.io$",
        "The gods are wise, but do not know of the site",
        "high",
    ),
    (
        "Zendesk",
        r"\.zendesk\.com$",
        "Help Center Closed",
        "high",
    ),
    (
        "Unbounce",
        r"\.unbouncepages\.com$",
        "The requested URL was not found on this server",
        "medium",
    ),
    (
        "Surge.sh",
        r"\.surge\.sh$",
        "project not found",
        "high",
    ),
    (
        "Fly.io",
        r"\.fly\.dev$",
        "404 Not Found",
        "medium",
    ),
    (
        "Netlify",
        r"\.netlify\.(app|com)$",
        "Not Found - Request ID",
        "high",
    ),
    (
        "Bitbucket",
        r"\.bitbucket\.io$",
        "Repository not found",
        "high",
    ),
    (
        "WordPress.com",
        r"\.wordpress\.com$",
        "Do you want to register",
        "high",
    ),
    (
        "Cargo Collective",
        r"\.cargocollective\.com$",
        "404 Not Found",
        "medium",
    ),
    (
        "Tilda",
        r"\.tilda\.(ws|cc)$",
        "Please renew your subscription",
        "high",
    ),
    (
        "Azure (cloudapp)",
        r"\.cloudapp\.azure\.com$",
        "404 Web Site not found",
        "high",
    ),
    (
        "Azure (web)",
        r"\.azurewebsites\.net$",
        "404 Web Site not found",
        "high",
    ),
    (
        "Azure (TrafficManager)",
        r"\.trafficmanager\.net$",
        "404 Web Site not found",
        "high",
    ),
]


def _extract_domain(target: str, target_raw: str) -> str:
    """Extract base domain from target."""
    raw = target_raw or target
    if re.match(r"^https?://", raw, re.I):
        parsed = urllib.parse.urlparse(raw)
        host = parsed.hostname or target
    else:
        host = target

    host = host.split(":")[0].strip().lower()

    if re.match(r"^\d+\.\d+\.\d+\.\d+$", host):
        return ""

    parts = host.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host


async def _resolve_cname(hostname: str, timeout: float = 5.0) -> str | None:
    """
    Resolve a CNAME for the given hostname.
    Uses a raw DNS query over UDP to extract CNAME records, since
    socket.getaddrinfo does not expose CNAME data.
    Falls back to checking if getaddrinfo fails (indicating dangling record).
    """
    import struct

    def _build_dns_query(name: str) -> bytes:
        """Build a DNS query for CNAME (type 5) records."""
        txn_id = b"\xaa\xbb"
        flags = b"\x01\x00"  # standard query, recursion desired
        counts = b"\x00\x01\x00\x00\x00\x00\x00\x00"
        qname = b""
        for label in name.rstrip(".").split("."):
            qname += bytes([len(label)]) + label.encode("ascii")
        qname += b"\x00"
        # QTYPE=CNAME(5), QCLASS=IN(1)
        question = qname + b"\x00\x05\x00\x01"
        return txn_id + flags + counts + question

    def _parse_cname_response(data: bytes) -> str | None:
        """Extract CNAME from DNS response (simplified parser)."""
        if len(data) < 12:
            return None
        ancount = struct.unpack("!H", data[6:8])[0]
        if ancount == 0:
            return None

        # Skip header (12 bytes) and question section
        offset = 12
        # Skip QNAME
        while offset < len(data):
            length = data[offset]
            if length == 0:
                offset += 1
                break
            if length >= 192:  # compression pointer
                offset += 2
                break
            offset += 1 + length
        # Skip QTYPE and QCLASS
        offset += 4

        # Parse first answer
        if offset >= len(data):
            return None

        # Read name (may be compressed)
        def read_name(data: bytes, off: int) -> tuple[str, int]:
            labels = []
            jumped = False
            original_off = off
            max_jumps = 10
            jumps = 0
            while off < len(data) and jumps < max_jumps:
                length = data[off]
                if length == 0:
                    off += 1
                    break
                if length >= 192:
                    pointer = struct.unpack("!H", data[off:off + 2])[0] & 0x3FFF
                    if not jumped:
                        original_off = off + 2
                    off = pointer
                    jumped = True
                    jumps += 1
                    continue
                off += 1
                labels.append(data[off:off + length].decode("ascii", errors="ignore"))
                off += length
            name = ".".join(labels)
            return name, original_off if jumped else off

        # Skip answer name
        _, offset = read_name(data, offset)

        if offset + 10 > len(data):
            return None

        rtype = struct.unpack("!H", data[offset:offset + 2])[0]
        offset += 8  # skip type(2) + class(2) + ttl(4)
        rdlength = struct.unpack("!H", data[offset:offset + 2])[0]
        offset += 2

        if rtype == 5 and rdlength > 0:  # CNAME
            cname, _ = read_name(data, offset)
            return cname if cname else None

        return None

    try:
        query = _build_dns_query(hostname)
        loop = asyncio.get_event_loop()

        def _udp_query():
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            try:
                # Use Google public DNS
                sock.sendto(query, ("8.8.8.8", 53))
                data, _ = sock.recvfrom(4096)
                return _parse_cname_response(data)
            finally:
                sock.close()

        return await asyncio.wait_for(
            loop.run_in_executor(None, _udp_query),
            timeout=timeout,
        )
    except Exception:
        return None


async def _check_http_fingerprint(
    subdomain: str, fingerprint_text: str, timeout: float = 8.0
) -> bool:
    """Check if the subdomain's HTTP response contains a takeover fingerprint."""
    for scheme in ("https", "http"):
        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(timeout),
                follow_redirects=True,
                verify=False,
                headers={"User-Agent": "VulnScan/2.1"},
            ) as client:
                resp = await client.get(f"{scheme}://{subdomain}/")
                body = resp.text[:10000]
                if fingerprint_text.lower() in body.lower():
                    return True
        except Exception:
            continue
    return False


async def _can_resolve(hostname: str, timeout: float = 3.0) -> bool:
    """Check if hostname resolves to any IP address."""
    loop = asyncio.get_event_loop()
    try:
        result = await asyncio.wait_for(
            loop.getaddrinfo(hostname, None, family=socket.AF_INET),
            timeout=timeout,
        )
        return bool(result)
    except Exception:
        return False


class Check(Plugin):
    async def run(self, target: str, ctx) -> PluginResult:
        target_raw = ctx.get("target_raw", target)
        findings: list[Finding] = []
        takeover_results: list[dict] = []

        domain = _extract_domain(target, target_raw)
        if not domain:
            return PluginResult(artifacts={"recon.subdomain_takeover": []})

        # Gather subdomains from previous plugins
        subdomains: list[str] = []

        # From subfinder / DNS enum
        sub_data = ctx.get("recon.subdomains", []) or []
        for item in sub_data:
            if isinstance(item, dict):
                hostname = item.get("hostname", "")
                if hostname:
                    subdomains.append(hostname)
            elif isinstance(item, str):
                subdomains.append(item)

        # Also check the main domain and www
        subdomains.append(domain)
        subdomains.append(f"www.{domain}")

        # De-duplicate
        subdomains = list(set(s.lower().strip().rstrip(".") for s in subdomains if s))

        if not subdomains:
            findings.append(Finding(
                severity="info",
                plugin_id=META.plugin_id,
                title=f"No subdomains to check for takeover ({domain})",
                evidence=f"domain={domain}",
                affected=target,
                fingerprint=stable_fingerprint(target, META.plugin_id, "no_subs"),
            ))
            return PluginResult(
                findings=findings,
                artifacts={"recon.subdomain_takeover": []},
            )

        # Check each subdomain for CNAME + takeover fingerprint
        sem = asyncio.Semaphore(10)
        checked = 0
        max_checks = 100  # Cap to avoid excessive DNS queries

        async def check_subdomain(sub: str):
            nonlocal checked
            if checked >= max_checks:
                return
            async with sem:
                checked += 1
                cname = await _resolve_cname(sub)
                if not cname:
                    return

                cname_lower = cname.lower().rstrip(".")

                # Check against known vulnerable services
                for service, cname_pat, http_fp, severity in _TAKEOVER_FINGERPRINTS:
                    if not re.search(cname_pat, cname_lower, re.I):
                        continue

                    # Check if CNAME target resolves (if it doesn't, strong signal)
                    cname_resolves = await _can_resolve(cname_lower)

                    # Check HTTP fingerprint
                    http_match = await _check_http_fingerprint(sub, http_fp)

                    if http_match or not cname_resolves:
                        confidence = 0.90 if http_match else 0.70
                        fp = stable_fingerprint(
                            target, META.plugin_id, "takeover", sub, service
                        )

                        evidence_parts = [
                            f"subdomain={sub}",
                            f"cname={cname_lower}",
                            f"service={service}",
                            f"cname_resolves={cname_resolves}",
                            f"http_fingerprint_match={http_match}",
                        ]

                        findings.append(Finding(
                            severity=severity,
                            plugin_id=META.plugin_id,
                            title=f"Subdomain takeover candidate: {sub} ({service})",
                            description=(
                                f"The subdomain {sub} has a CNAME record pointing to "
                                f"{cname_lower} ({service}), which appears to be unclaimed. "
                                f"An attacker could register this resource on {service} and "
                                f"serve arbitrary content under {sub}, enabling phishing, "
                                f"cookie theft, and credential harvesting."
                            ),
                            evidence=" ".join(evidence_parts),
                            affected=sub,
                            fingerprint=fp,
                            confidence=confidence,
                            remediation=(
                                f"[CRITICAL — Subdomain Takeover]\n"
                                f"Subdomain: {sub}\n"
                                f"CNAME target: {cname_lower}\n"
                                f"Service: {service}\n\n"
                                f"[IMMEDIATE ACTION]\n"
                                f"1. Remove the dangling CNAME record for {sub}\n"
                                f"   OR claim the resource on {service} before an attacker does\n"
                                f"2. Audit all CNAME records for similar dangling references\n\n"
                                f"[PREVENTION]\n"
                                f"- Remove DNS records when decommissioning services\n"
                                f"- Monitor CNAME targets for availability changes\n"
                                f"- Implement DNS record lifecycle management\n"
                                f"- Use CNAME monitoring tools to detect dangling records"
                            ),
                            references=[
                                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover",
                                "https://cwe.mitre.org/data/definitions/284.html",
                            ],
                        ))

                        takeover_results.append({
                            "subdomain": sub,
                            "cname": cname_lower,
                            "service": service,
                            "confirmed": http_match,
                            "severity": severity,
                        })
                    break  # only match first service per subdomain

        await asyncio.gather(
            *[check_subdomain(sub) for sub in subdomains[:max_checks]],
            return_exceptions=True,
        )

        # Summary finding
        if takeover_results:
            fp_summary = stable_fingerprint(
                target, META.plugin_id, "summary", str(len(takeover_results))
            )
            findings.append(Finding(
                severity="info",
                plugin_id=META.plugin_id,
                title=(
                    f"Subdomain takeover scan: {len(takeover_results)} candidate(s) "
                    f"found for {domain}"
                ),
                description=(
                    f"Checked {checked} subdomain(s) for dangling CNAME records. "
                    f"Found {len(takeover_results)} potential takeover candidate(s)."
                ),
                evidence=(
                    f"domain={domain} checked={checked} "
                    f"candidates={len(takeover_results)} "
                    f"services={list(set(r['service'] for r in takeover_results))}"
                ),
                affected=target,
                fingerprint=fp_summary,
                confidence=0.95,
                remediation=(
                    "Review all identified subdomain takeover candidates and remediate "
                    "by removing dangling DNS records or reclaiming the external resources."
                ),
            ))
        else:
            fp_clean = stable_fingerprint(target, META.plugin_id, "clean")
            findings.append(Finding(
                severity="info",
                plugin_id=META.plugin_id,
                title=f"No subdomain takeover candidates found for {domain}",
                description=(
                    f"Checked {checked} subdomain(s) for dangling CNAME records "
                    f"pointing to unclaimed third-party services. No takeover "
                    f"candidates were detected."
                ),
                evidence=f"domain={domain} checked={checked} candidates=0",
                affected=target,
                fingerprint=fp_clean,
                confidence=1.0,
            ))

        return PluginResult(
            findings=findings,
            artifacts={"recon.subdomain_takeover": takeover_results},
        )
