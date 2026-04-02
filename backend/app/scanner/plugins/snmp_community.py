"""
SNMP Community String Scanner — checks for default/weak SNMP community strings.

Tests UDP port 161 for SNMP v1/v2c with common community strings:
  - public, private, community, manager, admin, etc.

SNMP with default community strings allows attackers to enumerate system info,
network interfaces, routing tables, ARP caches, and (with write access) modify
device configuration remotely.

All tests are read-only (SNMP GET-REQUEST for sysDescr OID).
"""
import asyncio
import logging
import socket
import struct

from app.scanner.plugins.base import Finding, Plugin, PluginMeta, PluginResult
from app.scanner.context import stable_fingerprint

logger = logging.getLogger("vulnscan.snmp_community")

META = PluginMeta(
    plugin_id="infra.snmp.community",
    name="SNMP Community String Scanner",
    category="network",
    depends_on=["net.port.discovery.v2"],
    consumes=["net.open_ports"],
    provides=["infra.snmp.findings"],
    enabled_by_default=True,
    timeout_seconds=15.0,
)

# Common default community strings (read-only probe)
_COMMUNITY_STRINGS = [
    "public",
    "private",
    "community",
    "manager",
    "admin",
    "default",
    "snmp",
    "monitor",
    "read",
    "write",
    "secret",
    "cisco",
    "router",
    "switch",
    "test",
]

# OID for sysDescr.0 (1.3.6.1.2.1.1.1.0)
_SYS_DESCR_OID = b"\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00"


def _build_snmp_get(community: str, request_id: int = 1) -> bytes:
    """Build an SNMPv2c GET-REQUEST for sysDescr.0."""
    comm_bytes = community.encode("ascii")

    # Variable binding: OID + NULL value
    oid_value = _SYS_DESCR_OID + b"\x05\x00"  # NULL
    varbind = b"\x30" + bytes([len(oid_value)]) + oid_value
    varbind_list = b"\x30" + bytes([len(varbind)]) + varbind

    # Request ID
    rid = struct.pack(">i", request_id)
    rid_tlv = b"\x02\x04" + rid

    # Error status + error index (both 0)
    err_status = b"\x02\x01\x00"
    err_index = b"\x02\x01\x00"

    # PDU: GET-REQUEST (0xA0)
    pdu_value = rid_tlv + err_status + err_index + varbind_list
    pdu = b"\xa0" + bytes([len(pdu_value)]) + pdu_value

    # Version: SNMPv2c = 1
    version = b"\x02\x01\x01"

    # Community string
    comm_tlv = b"\x04" + bytes([len(comm_bytes)]) + comm_bytes

    # SEQUENCE wrapper
    msg_value = version + comm_tlv + pdu
    message = b"\x30" + bytes([len(msg_value)]) + msg_value

    return message


def _parse_snmp_response(data: bytes) -> str | None:
    """Extract sysDescr string from SNMP GET-RESPONSE. Returns None on failure."""
    try:
        if not data or data[0] != 0x30:
            return None
        # Look for an OCTET STRING (0x04) containing the sysDescr value
        # Walk through to find the response value after the OID
        idx = data.find(_SYS_DESCR_OID)
        if idx < 0:
            # Fallback: find any OCTET STRING after PDU tag 0xA2 (GET-RESPONSE)
            idx = data.find(b"\xa2")
            if idx < 0:
                return ""  # Got a response but couldn't parse
        # Search for OCTET STRING tag after OID
        pos = idx
        while pos < len(data) - 2:
            if data[pos] == 0x04:  # OCTET STRING
                length = data[pos + 1]
                value = data[pos + 2:pos + 2 + length]
                return value.decode("utf-8", errors="ignore")
            pos += 1
        return ""
    except Exception:
        return None


async def _probe_community(host: str, community: str,
                           timeout: float = 2.0) -> tuple[str, str | None]:
    """Send SNMP GET to host with given community. Returns (community, sysDescr|None)."""
    loop = asyncio.get_event_loop()
    packet = _build_snmp_get(community)

    def _udp_probe():
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.sendto(packet, (host, 161))
            data, _ = sock.recvfrom(4096)
            return _parse_snmp_response(data)
        except (socket.timeout, OSError):
            return None
        finally:
            sock.close()

    try:
        result = await asyncio.wait_for(
            loop.run_in_executor(None, _udp_probe), timeout=timeout + 1
        )
        return community, result
    except (asyncio.TimeoutError, Exception):
        return community, None


class Check(Plugin):
    async def run(self, target: str, ctx) -> PluginResult:
        open_ports = ctx.get("net.open_ports", []) or []
        findings: list[Finding] = []

        # SNMP uses UDP 161 — port scan may or may not detect UDP
        # Always try if target is internal; skip only if we're sure it's not available
        scan_type = ctx.get("scan_type", "internal")
        # For external scans, only check if port 161 was found
        if scan_type == "external" and 161 not in open_ports:
            return PluginResult(artifacts={"infra.snmp.findings": 0})

        # Probe all community strings concurrently
        tasks = [_probe_community(target, cs) for cs in _COMMUNITY_STRINGS]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        accepted = []
        for r in results:
            if isinstance(r, Exception):
                continue
            community, sys_descr = r
            if sys_descr is not None:
                accepted.append((community, sys_descr))

        if not accepted:
            return PluginResult(artifacts={"infra.snmp.findings": 0})

        community_names = [c for c, _ in accepted]
        # Primary finding: default community strings accepted
        severity = "critical" if any(
            c in ("public", "private") for c in community_names
        ) else "high"

        sample_descr = next((d for _, d in accepted if d), "")

        fp = stable_fingerprint(target, META.plugin_id, "default_community")
        findings.append(Finding(
            severity=severity,
            plugin_id=META.plugin_id,
            title=f"SNMP default community string(s) accepted: {', '.join(community_names)}",
            description=(
                f"SNMP on {target}:161 accepts the following default community strings: "
                f"{', '.join(community_names)}. An attacker can use these to enumerate "
                f"system information, network interfaces, routing tables, ARP caches, "
                f"and installed software. With 'private' (write) access, device "
                f"configuration can be modified remotely."
            ),
            evidence=(
                f"host={target} port=161 protocol=SNMPv2c "
                f"accepted_communities={','.join(community_names)} "
                f"sysDescr={sample_descr[:200]}"
            ),
            affected=f"{target}:161",
            fingerprint=fp,
            confidence=0.95,
            remediation=(
                "[CRITICAL — Default SNMP Community Strings]\n"
                "SNMP is accessible with default/guessable community strings.\n\n"
                "Immediate remediation:\n"
                "1. Change community strings to strong, random values\n"
                "2. Upgrade to SNMPv3 with authentication and encryption:\n"
                "   - Use authPriv security level\n"
                "   - Configure SHA-256 auth + AES-256 encryption\n"
                "3. Restrict SNMP access via ACLs to management IPs only\n"
                "4. Disable SNMP if not needed\n"
                "5. If SNMPv2c required, use unique non-guessable strings\n"
                "6. Separate read-only and read-write communities\n\n"
                "Cisco example:\n"
                "  no snmp-server community public\n"
                "  no snmp-server community private\n"
                "  snmp-server community R4nd0mStr1ng RO 10\n"
                "  access-list 10 permit 10.0.0.0 0.0.0.255"
            ),
            references=[
                "https://cwe.mitre.org/data/definitions/1391.html",
                "https://www.cisco.com/c/en/us/support/docs/ip/simple-network-management-protocol-snmp/7282-12.html",
            ],
        ))

        # Extra finding if "private" (write) community is accepted
        if "private" in community_names:
            fp2 = stable_fingerprint(target, META.plugin_id, "write_community")
            findings.append(Finding(
                severity="critical",
                plugin_id=META.plugin_id,
                title="SNMP write community string 'private' accepted — RCE risk",
                description=(
                    f"The SNMP write community string 'private' is accepted on {target}:161. "
                    f"An attacker can modify device configuration, change routing tables, "
                    f"upload firmware, or disable security features. On some devices this "
                    f"enables remote code execution."
                ),
                evidence=f"host={target} port=161 write_community=private",
                affected=f"{target}:161",
                fingerprint=fp2,
                confidence=0.95,
                remediation=(
                    "[CRITICAL — SNMP Write Access]\n"
                    "Remove or change the 'private' community string immediately.\n"
                    "Upgrade to SNMPv3 with authPriv security level."
                ),
                references=[
                    "https://cwe.mitre.org/data/definitions/1391.html",
                ],
            ))

        return PluginResult(
            findings=findings,
            artifacts={"infra.snmp.findings": len(findings)},
        )
