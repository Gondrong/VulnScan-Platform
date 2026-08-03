"""
DNS History & Passive Intelligence Plugin
Combines Certificate Transparency logs, passive DNS resolution, and email
security checks (SPF/DMARC) to build a comprehensive view of a domain's
DNS footprint.

No external tool dependencies — uses httpx for HTTP and socket for DNS.
"""
import asyncio
import logging
import re
import socket
import urllib.parse

import httpx

from app.scanner.plugins.base import Finding, Plugin, PluginMeta, PluginResult
from app.scanner.context import stable_fingerprint

logger = logging.getLogger("vulnscan.plugin.dns_history")

META = PluginMeta(
    plugin_id="recon.dns_history",
    name="DNS History & Passive Intelligence",
    category="recon",
    depends_on=["fingerprint.http"],
    provides=["recon.dns_history"],
    enabled_by_default=True,
    timeout_seconds=30.0,
)

# crt.sh Certificate Transparency API
_CRTSH_API = "https://crt.sh/?q=%.{domain}&output=json"


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


async def _resolve_a(hostname: str, timeout: float = 3.0) -> list[str]:
    """Resolve hostname to A record IP addresses."""
    loop = asyncio.get_event_loop()
    try:
        result = await asyncio.wait_for(
            loop.getaddrinfo(hostname, None, family=socket.AF_INET),
            timeout=timeout,
        )
        return list({addr[4][0] for addr in result})
    except Exception:
        return []


async def _resolve_aaaa(hostname: str, timeout: float = 3.0) -> list[str]:
    """Resolve hostname to AAAA record IPv6 addresses."""
    loop = asyncio.get_event_loop()
    try:
        result = await asyncio.wait_for(
            loop.getaddrinfo(hostname, None, family=socket.AF_INET6),
            timeout=timeout,
        )
        return list({addr[4][0] for addr in result})
    except Exception:
        return []


async def _resolve_mx(domain: str, timeout: float = 5.0) -> list[str]:
    """
    Resolve MX records for a domain using a raw DNS UDP query.
    Returns list of mail exchanger hostnames.
    """
    import struct

    def _build_query(name: str, qtype: int) -> bytes:
        txn_id = b"\xcc\xdd"
        flags = b"\x01\x00"
        counts = b"\x00\x01\x00\x00\x00\x00\x00\x00"
        qname = b""
        for label in name.rstrip(".").split("."):
            qname += bytes([len(label)]) + label.encode("ascii")
        qname += b"\x00"
        question = qname + struct.pack("!HH", qtype, 1)
        return txn_id + flags + counts + question

    def _read_name(data: bytes, offset: int) -> tuple[str, int]:
        labels = []
        jumped = False
        original = offset
        max_jumps = 10
        jumps = 0
        while offset < len(data) and jumps < max_jumps:
            length = data[offset]
            if length == 0:
                offset += 1
                break
            if length >= 192:
                pointer = struct.unpack("!H", data[offset:offset + 2])[0] & 0x3FFF
                if not jumped:
                    original = offset + 2
                offset = pointer
                jumped = True
                jumps += 1
                continue
            offset += 1
            labels.append(data[offset:offset + length].decode("ascii", errors="ignore"))
            offset += length
        return ".".join(labels), original if jumped else offset

    def _udp_query() -> list[str]:
        query = _build_query(domain, 15)  # MX = 15
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        mx_hosts = []
        try:
            sock.sendto(query, ("8.8.8.8", 53))
            data, _ = sock.recvfrom(4096)
            if len(data) < 12:
                return []
            ancount = struct.unpack("!H", data[6:8])[0]
            # Skip header + question
            offset = 12
            while offset < len(data) and data[offset] != 0:
                if data[offset] >= 192:
                    offset += 2
                    break
                offset += 1 + data[offset]
            else:
                offset += 1
            offset += 4  # QTYPE + QCLASS

            for _ in range(ancount):
                if offset >= len(data):
                    break
                _, offset = _read_name(data, offset)
                if offset + 10 > len(data):
                    break
                rtype = struct.unpack("!H", data[offset:offset + 2])[0]
                rdlength = struct.unpack("!H", data[offset + 8:offset + 10])[0]
                offset += 10
                if rtype == 15 and rdlength >= 4:  # MX
                    # Skip 2-byte preference
                    mx_name, _ = _read_name(data, offset + 2)
                    if mx_name:
                        mx_hosts.append(mx_name)
                offset += rdlength
        finally:
            sock.close()
        return mx_hosts

    loop = asyncio.get_event_loop()
    try:
        return await asyncio.wait_for(
            loop.run_in_executor(None, _udp_query),
            timeout=timeout,
        )
    except Exception:
        return []


async def _resolve_txt(domain: str, timeout: float = 5.0) -> list[str]:
    """
    Resolve TXT records for a domain using a raw DNS UDP query.
    Returns list of TXT record strings.
    """
    import struct

    def _build_query(name: str, qtype: int) -> bytes:
        txn_id = b"\xee\xff"
        flags = b"\x01\x00"
        counts = b"\x00\x01\x00\x00\x00\x00\x00\x00"
        qname = b""
        for label in name.rstrip(".").split("."):
            qname += bytes([len(label)]) + label.encode("ascii")
        qname += b"\x00"
        question = qname + struct.pack("!HH", qtype, 1)
        return txn_id + flags + counts + question

    def _read_name(data: bytes, offset: int) -> tuple[str, int]:
        labels = []
        jumped = False
        original = offset
        max_jumps = 10
        jumps = 0
        while offset < len(data) and jumps < max_jumps:
            length = data[offset]
            if length == 0:
                offset += 1
                break
            if length >= 192:
                pointer = struct.unpack("!H", data[offset:offset + 2])[0] & 0x3FFF
                if not jumped:
                    original = offset + 2
                offset = pointer
                jumped = True
                jumps += 1
                continue
            offset += 1
            labels.append(data[offset:offset + length].decode("ascii", errors="ignore"))
            offset += length
        return ".".join(labels), original if jumped else offset

    def _udp_query() -> list[str]:
        query = _build_query(domain, 16)  # TXT = 16
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        txt_records = []
        try:
            sock.sendto(query, ("8.8.8.8", 53))
            data, _ = sock.recvfrom(4096)
            if len(data) < 12:
                return []
            ancount = struct.unpack("!H", data[6:8])[0]
            # Skip header + question
            offset = 12
            while offset < len(data) and data[offset] != 0:
                if data[offset] >= 192:
                    offset += 2
                    break
                offset += 1 + data[offset]
            else:
                offset += 1
            offset += 4  # QTYPE + QCLASS

            for _ in range(ancount):
                if offset >= len(data):
                    break
                _, offset = _read_name(data, offset)
                if offset + 10 > len(data):
                    break
                rtype = struct.unpack("!H", data[offset:offset + 2])[0]
                rdlength = struct.unpack("!H", data[offset + 8:offset + 10])[0]
                offset += 10
                if rtype == 16 and rdlength > 0:  # TXT
                    # TXT records: one or more <length><text> segments
                    txt_end = offset + rdlength
                    txt_parts = []
                    pos = offset
                    while pos < txt_end:
                        seg_len = data[pos]
                        pos += 1
                        if pos + seg_len <= txt_end:
                            txt_parts.append(
                                data[pos:pos + seg_len].decode("utf-8", errors="ignore")
                            )
                        pos += seg_len
                    if txt_parts:
                        txt_records.append("".join(txt_parts))
                offset += rdlength
        finally:
            sock.close()
        return txt_records

    loop = asyncio.get_event_loop()
    try:
        return await asyncio.wait_for(
            loop.run_in_executor(None, _udp_query),
            timeout=timeout,
        )
    except Exception:
        return []


class Check(Plugin):
    async def run(self, target: str, ctx) -> PluginResult:
        target_raw = ctx.get("target_raw", target)
        findings: list[Finding] = []
        dns_history: dict = {
            "ct_subdomains": [],
            "dns_records": [],
            "spf": None,
            "dmarc": None,
            "mx": [],
        }

        domain = _extract_domain(target, target_raw)
        if not domain:
            return PluginResult(artifacts={"recon.dns_history": dns_history})

        # ── Phase 1: Certificate Transparency via crt.sh ──────────────
        ct_subdomains: list[str] = []
        try:
            ct_url = _CRTSH_API.format(domain=urllib.parse.quote(domain))
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(20.0),
                follow_redirects=True,
                verify=True,
                headers={"User-Agent": "VulnScan/2.1"},
            ) as client:
                resp = await client.get(ct_url)
                resp.raise_for_status()
                data = resp.json()

            if isinstance(data, list):
                seen: set[str] = set()
                for entry in data:
                    common_name = entry.get("common_name", "")
                    name_value = entry.get("name_value", "")
                    for name in [common_name] + name_value.split("\n"):
                        name = name.strip().lower().lstrip("*.")
                        if (
                            name
                            and name.endswith(domain)
                            and name not in seen
                            and len(name) < 253
                        ):
                            seen.add(name)
                            ct_subdomains.append(name)

        except Exception as e:
            logger.debug("crt.sh query failed for %s: %s", domain, e)
            findings.append(Finding(
                severity="info",
                plugin_id=META.plugin_id,
                title=f"Certificate Transparency query failed for {domain}",
                evidence=f"error={str(e)[:200]}",
                affected=target,
                fingerprint=stable_fingerprint(target, META.plugin_id, "ct_error"),
                remediation=(
                    "crt.sh query failed. This may be due to network restrictions "
                    "or rate limiting. CT log data is valuable for discovering the "
                    "full scope of an organization's domain footprint."
                ),
            ))

        dns_history["ct_subdomains"] = ct_subdomains

        if ct_subdomains:
            fp_ct = stable_fingerprint(
                target, META.plugin_id, "ct_subs", str(len(ct_subdomains))
            )
            findings.append(Finding(
                severity="info",
                plugin_id=META.plugin_id,
                title=(
                    f"CT logs: {len(ct_subdomains)} subdomain(s) discovered for {domain}"
                ),
                description=(
                    f"Certificate Transparency logs reveal {len(ct_subdomains)} unique "
                    f"subdomain(s) for {domain}. These subdomains have had SSL/TLS "
                    f"certificates issued, confirming they are (or were) active."
                ),
                evidence=(
                    f"domain={domain} ct_subdomains={len(ct_subdomains)} "
                    f"sample={sorted(ct_subdomains)[:20]}"
                ),
                affected=target,
                fingerprint=fp_ct,
                confidence=0.95,
                remediation=(
                    f"[INFO] {len(ct_subdomains)} subdomains found in CT logs\n\n"
                    f"[ACTION]\n"
                    f"1. Verify all subdomains are authorized and intentional\n"
                    f"2. Check for decommissioned services with dangling DNS records\n"
                    f"3. Ensure certificates are current and properly configured\n"
                    f"4. Monitor CT logs for unauthorized certificate issuance "
                    f"(consider CAA records)\n\n"
                    f"[SUBDOMAINS]\n"
                    + "\n".join(f"  - {s}" for s in sorted(ct_subdomains)[:25])
                ),
                references=[
                    "https://certificate.transparency.dev/",
                    "https://crt.sh/",
                ],
            ))

        # ── Phase 2: DNS resolution for discovered subdomains ─────────
        # Resolve A/AAAA for a sample of discovered subdomains
        sem = asyncio.Semaphore(15)
        dns_records: list[dict] = []
        resolve_targets = ct_subdomains[:50]  # Cap to avoid excessive queries
        # Always include the main domain
        if domain not in resolve_targets:
            resolve_targets.insert(0, domain)

        async def resolve_subdomain(sub: str):
            async with sem:
                record: dict = {"hostname": sub, "a": [], "aaaa": []}
                a_ips = await _resolve_a(sub, timeout=3.0)
                if a_ips:
                    record["a"] = a_ips
                aaaa_ips = await _resolve_aaaa(sub, timeout=3.0)
                if aaaa_ips:
                    record["aaaa"] = aaaa_ips
                if record["a"] or record["aaaa"]:
                    dns_records.append(record)

        await asyncio.gather(
            *[resolve_subdomain(sub) for sub in resolve_targets],
            return_exceptions=True,
        )

        dns_history["dns_records"] = dns_records

        # ── Phase 3: MX records ───────────────────────────────────────
        mx_hosts = await _resolve_mx(domain)
        dns_history["mx"] = mx_hosts

        if mx_hosts:
            fp_mx = stable_fingerprint(target, META.plugin_id, "mx", domain)
            findings.append(Finding(
                severity="info",
                plugin_id=META.plugin_id,
                title=f"MX records found for {domain}: {len(mx_hosts)} mail server(s)",
                evidence=f"domain={domain} mx={mx_hosts}",
                affected=target,
                fingerprint=fp_mx,
                confidence=1.0,
            ))

        # ── Phase 4: SPF check ────────────────────────────────────────
        txt_records = await _resolve_txt(domain)
        spf_record = None
        for txt in txt_records:
            if txt.strip().startswith("v=spf1"):
                spf_record = txt.strip()
                break

        dns_history["spf"] = spf_record

        if not spf_record:
            fp_spf = stable_fingerprint(target, META.plugin_id, "no_spf", domain)
            findings.append(Finding(
                severity="medium",
                plugin_id=META.plugin_id,
                title=f"Missing SPF record for {domain}",
                description=(
                    f"No SPF (Sender Policy Framework) TXT record was found for {domain}. "
                    f"Without SPF, attackers can send emails that appear to come from "
                    f"{domain}, enabling phishing and business email compromise attacks."
                ),
                evidence=f"domain={domain} spf=missing txt_records={len(txt_records)}",
                affected=target,
                fingerprint=fp_spf,
                confidence=0.90,
                remediation=(
                    f"[EMAIL SECURITY — Missing SPF]\n"
                    f"Domain: {domain}\n\n"
                    f"[ACTION]\n"
                    f"1. Add an SPF TXT record to your DNS zone:\n"
                    f"   {domain}. IN TXT \"v=spf1 include:<your-mail-provider> -all\"\n"
                    f"2. Use '-all' (hard fail) to reject unauthorized senders\n"
                    f"3. Test with: nslookup -type=TXT {domain}\n\n"
                    f"[EXAMPLE]\n"
                    f"  v=spf1 include:_spf.google.com -all\n"
                    f"  v=spf1 include:spf.protection.outlook.com -all"
                ),
                references=[
                    "https://www.rfc-editor.org/rfc/rfc7208",
                    "https://dmarcian.com/spf-syntax-table/",
                ],
            ))
        else:
            # Check for overly permissive SPF
            if "+all" in spf_record or spf_record.endswith("?all"):
                fp_weak_spf = stable_fingerprint(
                    target, META.plugin_id, "weak_spf", domain
                )
                findings.append(Finding(
                    severity="medium",
                    plugin_id=META.plugin_id,
                    title=f"Weak SPF policy for {domain}",
                    description=(
                        f"The SPF record for {domain} uses a permissive policy "
                        f"(+all or ?all) that does not effectively prevent email spoofing."
                    ),
                    evidence=f"domain={domain} spf={spf_record}",
                    affected=target,
                    fingerprint=fp_weak_spf,
                    confidence=0.90,
                    remediation=(
                        f"[EMAIL SECURITY — Weak SPF]\n"
                        f"Current SPF: {spf_record}\n\n"
                        f"[ACTION]\n"
                        f"Change the SPF qualifier to '-all' (hard fail) to reject "
                        f"unauthorized senders. The current policy is too permissive."
                    ),
                    references=["https://www.rfc-editor.org/rfc/rfc7208"],
                ))

        # ── Phase 5: DMARC check ──────────────────────────────────────
        dmarc_domain = f"_dmarc.{domain}"
        dmarc_records = await _resolve_txt(dmarc_domain)
        dmarc_record = None
        for txt in dmarc_records:
            if txt.strip().startswith("v=DMARC1"):
                dmarc_record = txt.strip()
                break

        dns_history["dmarc"] = dmarc_record

        if not dmarc_record:
            fp_dmarc = stable_fingerprint(target, META.plugin_id, "no_dmarc", domain)
            findings.append(Finding(
                severity="medium",
                plugin_id=META.plugin_id,
                title=f"Missing DMARC record for {domain}",
                description=(
                    f"No DMARC (Domain-based Message Authentication, Reporting & "
                    f"Conformance) record was found for {domain}. Without DMARC, "
                    f"there is no policy telling receiving mail servers how to handle "
                    f"messages that fail SPF/DKIM checks, making the domain more "
                    f"susceptible to email spoofing."
                ),
                evidence=f"domain={domain} dmarc=missing checked={dmarc_domain}",
                affected=target,
                fingerprint=fp_dmarc,
                confidence=0.90,
                remediation=(
                    f"[EMAIL SECURITY — Missing DMARC]\n"
                    f"Domain: {domain}\n\n"
                    f"[ACTION]\n"
                    f"1. Add a DMARC TXT record:\n"
                    f"   _dmarc.{domain}. IN TXT "
                    f"\"v=DMARC1; p=quarantine; rua=mailto:dmarc@{domain}\"\n"
                    f"2. Start with p=none to monitor, then move to p=quarantine or "
                    f"p=reject\n"
                    f"3. Set up a mailbox or service to receive aggregate reports (rua)\n\n"
                    f"[RECOMMENDED POLICY]\n"
                    f"  v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s; "
                    f"rua=mailto:dmarc-reports@{domain}"
                ),
                references=[
                    "https://www.rfc-editor.org/rfc/rfc7489",
                    "https://dmarcian.com/dmarc-inspector/",
                ],
            ))
        else:
            # Check for weak DMARC policy
            policy_match = re.search(r"p\s*=\s*(\w+)", dmarc_record)
            policy = policy_match.group(1).lower() if policy_match else "none"
            if policy == "none":
                fp_weak_dmarc = stable_fingerprint(
                    target, META.plugin_id, "weak_dmarc", domain
                )
                findings.append(Finding(
                    severity="low",
                    plugin_id=META.plugin_id,
                    title=f"DMARC policy set to 'none' for {domain}",
                    description=(
                        f"The DMARC record for {domain} has policy p=none, which only "
                        f"monitors email but does not instruct receivers to quarantine or "
                        f"reject spoofed messages. This is useful for initial deployment "
                        f"but should be upgraded to p=quarantine or p=reject."
                    ),
                    evidence=f"domain={domain} dmarc={dmarc_record}",
                    affected=target,
                    fingerprint=fp_weak_dmarc,
                    confidence=0.85,
                    remediation=(
                        f"[EMAIL SECURITY — Weak DMARC]\n"
                        f"Current: {dmarc_record}\n\n"
                        f"[ACTION]\n"
                        f"After verifying SPF/DKIM alignment via DMARC reports, upgrade "
                        f"the policy from p=none to p=quarantine and eventually p=reject."
                    ),
                    references=["https://www.rfc-editor.org/rfc/rfc7489"],
                ))

        # ── Summary ───────────────────────────────────────────────────
        resolved_count = len(dns_records)
        fp_summary = stable_fingerprint(target, META.plugin_id, "summary", domain)
        findings.append(Finding(
            severity="info",
            plugin_id=META.plugin_id,
            title=f"DNS history summary for {domain}",
            description=(
                f"Passive DNS intelligence gathered for {domain}: "
                f"{len(ct_subdomains)} subdomain(s) from CT logs, "
                f"{resolved_count} resolving to IP addresses, "
                f"{len(mx_hosts)} MX record(s), "
                f"SPF={'present' if spf_record else 'missing'}, "
                f"DMARC={'present' if dmarc_record else 'missing'}."
            ),
            evidence=(
                f"domain={domain} ct_subdomains={len(ct_subdomains)} "
                f"resolved={resolved_count} mx={len(mx_hosts)} "
                f"spf={'yes' if spf_record else 'no'} "
                f"dmarc={'yes' if dmarc_record else 'no'}"
            ),
            affected=target,
            fingerprint=fp_summary,
            confidence=1.0,
        ))

        return PluginResult(
            findings=findings,
            artifacts={"recon.dns_history": dns_history},
        )
