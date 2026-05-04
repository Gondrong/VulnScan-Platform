"""
UDP Port Scanner — discovers responsive UDP services with protocol-specific probes.

UDP is harder than TCP: silence usually means filtered/closed/dropped, not open.
This plugin sends targeted probes (DNS query, NTP request, SNMP GET, etc.)
to known service ports and treats any response as confirmation that the
port is reachable. Ports without a known probe receive a small zero-byte
payload — those without responses are reported as 'open|filtered'.

Disabled by default — UDP scans are slow and noisy on tight budgets.
"""
import asyncio
import socket

from app.scanner.plugins.base import Finding, Plugin, PluginMeta, PluginResult
from app.scanner.context import stable_fingerprint

META = PluginMeta(
    plugin_id="net.port.discovery.udp",
    name="UDP Port Scanner",
    category="network",
    provides=["net.open_udp_ports", "net.udp_service_responses"],
    enabled_by_default=False,
    timeout_seconds=120.0,
)

# Top-N UDP ports by Nmap frequency, plus high-value extras (BACnet, IPMI, mDNS)
TOP_UDP_PORTS = [
    53, 67, 68, 69, 111, 123, 135, 137, 138, 139, 161, 162, 445, 500,
    514, 520, 623, 631, 1194, 1434, 1701, 1812, 1813, 1900, 2049, 3702,
    4500, 5060, 5353, 5683, 11211, 17185, 27015, 32768, 47808,
]

SERVICE_NAMES = {
    53: "dns", 67: "dhcps", 68: "dhcpc", 69: "tftp", 111: "rpcbind",
    123: "ntp", 135: "msrpc", 137: "netbios-ns", 138: "netbios-dgm",
    139: "netbios-ssn", 161: "snmp", 162: "snmp-trap", 445: "microsoft-ds",
    500: "isakmp", 514: "syslog", 520: "rip", 623: "ipmi-rmcp", 631: "ipp",
    1194: "openvpn", 1434: "mssql-monitor", 1701: "l2tp",
    1812: "radius-auth", 1813: "radius-acct", 1900: "ssdp", 2049: "nfs",
    3702: "ws-discovery", 4500: "isakmp-natt", 5060: "sip", 5353: "mdns",
    5683: "coap", 11211: "memcached", 17185: "vxworks-wdb", 27015: "steam",
    32768: "rpc-nfs", 47808: "bacnet",
}

# Risky exposed UDP services that warrant a separate finding when responsive
RISKY_SERVICES = {
    53: ("dns", "medium",
         "Open DNS resolver. If recursion is enabled for arbitrary clients this can be abused for amplification DDoS. Disable recursion for non-trusted networks (BIND: allow-recursion, dnsmasq: --no-resolv)."),
    69: ("tftp", "high",
         "TFTP has no authentication and transmits files in plaintext. Replace with SFTP/HTTPS or restrict to a dedicated management VLAN."),
    111: ("rpcbind", "medium",
         "rpcbind/portmapper exposed. Frequently abused for amplification reflection. Restrict to internal networks via firewall and disable on hosts that do not require RPC."),
    123: ("ntp", "medium",
         "NTP service exposed. Disable monlist (CVE-2013-5211 amplification). Upgrade ntpd to 4.2.7p26+ or migrate to chrony."),
    137: ("netbios-ns", "medium",
         "NetBIOS Name Service exposed. Block at the perimeter — used for host enumeration and relay attacks (LLMNR/NBT-NS poisoning)."),
    161: ("snmp", "high",
         "SNMP exposed. Use SNMPv3 with authPriv only. Disable v1/v2c, restrict to a monitoring subnet, and rotate any default community strings (public/private)."),
    500: ("isakmp", "info",
         "IKE/IPsec endpoint reachable. Ensure aggressive mode is disabled and only IKEv2 with strong PSKs/certificates is permitted."),
    623: ("ipmi-rmcp", "high",
         "IPMI/RMCP exposed. IPMI 2.0 has known authentication-bypass weaknesses (cipher 0, RAKP hash leak). Restrict to a dedicated out-of-band management network."),
    1900: ("ssdp", "medium",
         "SSDP/UPnP exposed. Disable UPnP on internet-facing devices — used for amplification DDoS (CVE-2014-3936)."),
    2049: ("nfs", "high",
         "NFS exposed without firewall restrictions. Use Kerberos auth (NFSv4 sec=krb5p), restrict by IP, or move to an internal-only network."),
    5353: ("mdns", "medium",
         "mDNS reachable from outside the local segment. Block at perimeter — leaks hostnames/services and is used for reflection amplification."),
    11211: ("memcached", "critical",
         "Memcached UDP exposed (CVE-2018-1000115). Massive amplification factor (~50,000x). Disable UDP entirely (-U 0) or bind to localhost. Block 11211/UDP at the perimeter."),
    47808: ("bacnet", "high",
         "BACnet (building automation / OT) reachable. ICS/OT systems must never face the internet. Air-gap or segregate to an OT VLAN with strict firewalling."),
}


# ─── Protocol probes ──────────────────────────────────────────────────────────

def _probe_dns() -> bytes:
    # DNS query for 'version.bind.' TXT in CHAOS class — a standard fingerprint probe
    return (
        b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        b"\x07version\x04bind\x00\x00\x10\x00\x03"
    )

def _probe_ntp() -> bytes:
    # Mode 3 (client) v2 NTP packet
    return b"\x17\x00\x03\x2a" + b"\x00" * 44

def _probe_snmp() -> bytes:
    # SNMPv1 GetRequest community="public" sysDescr.0 (1.3.6.1.2.1.1.1.0)
    return bytes.fromhex(
        "302902010004067075626c6963a01c020401020304020100020100"
        "300e300c06082b06010201010100050500"
    )

def _probe_netbios_ns() -> bytes:
    # NBNS node-status request, encoded wildcard '*' name
    name = b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00"
    return b"\x80\xf4\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00" + name + b"\x00\x21\x00\x01"

def _probe_mdns() -> bytes:
    # mDNS query for _services._dns-sd._udp.local.  PTR
    return bytes.fromhex(
        "0000010000010000000000000d5f73657276696365730a5f646e732d736400"
        "045f7564700000050001"
    )

def _probe_ssdp() -> bytes:
    return (
        b"M-SEARCH * HTTP/1.1\r\n"
        b"HOST: 239.255.255.250:1900\r\n"
        b'MAN: "ssdp:discover"\r\n'
        b"MX: 1\r\n"
        b"ST: ssdp:all\r\n\r\n"
    )

def _probe_memcached() -> bytes:
    # UDP memcached: 8-byte header + ascii 'stats\r\n'
    return b"\x00\x00\x00\x00\x00\x01\x00\x00stats\r\n"

def _probe_ike() -> bytes:
    # ISAKMP main-mode SA proposal, single transform AES-128/SHA1/PSK/Group2
    body = bytes.fromhex(
        "0000000000000000000000000000000001100200000000000000009c"
        "0d0000300000000100000001000000240101000080010001800200018003000180040002800b0001800c0e10"
    )
    return body

def _probe_default() -> bytes:
    # Generic 4-byte zero-pad for ports without a known probe
    return b"\x00\x00\x00\x00"

PROBES = {
    53: _probe_dns,
    123: _probe_ntp,
    161: _probe_snmp,
    137: _probe_netbios_ns,
    5353: _probe_mdns,
    1900: _probe_ssdp,
    11211: _probe_memcached,
    500: _probe_ike,
}


def _udp_probe_blocking(host: str, port: int, payload: bytes, timeout: float) -> bytes | None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(payload, (host, port))
        data, _ = sock.recvfrom(4096)
        return data
    except (socket.timeout, OSError):
        return None
    finally:
        try:
            sock.close()
        except Exception:
            pass


async def _probe_port(host: str, port: int, timeout: float, sem: asyncio.Semaphore) -> tuple[int, bytes | None]:
    payload = (PROBES.get(port) or _probe_default)()
    async with sem:
        try:
            data = await asyncio.to_thread(_udp_probe_blocking, host, port, payload, timeout)
            return port, data
        except Exception:
            return port, None


class Check(Plugin):
    async def run(self, target: str, ctx) -> PluginResult:
        target_raw = ctx.get("target_raw", target)
        scan_type = ctx.get("scan_type", "internal")
        options = (ctx.get("profile_options") or {}).get("udp", {}) or {}

        # URLs aren't meaningful for UDP — skip cleanly
        if isinstance(target_raw, str) and target_raw.startswith("http"):
            return PluginResult(
                findings=[],
                artifacts={"net.open_udp_ports": [], "net.udp_service_responses": {}},
            )

        mode = options.get("mode", "top")
        timeout = float(options.get("timeout", 2.0 if scan_type == "internal" else 4.0))
        concurrency = int(options.get("concurrency", 30))

        if mode == "common":
            ports_to_check = [53, 123, 161, 500, 1900, 5353, 11211]
        elif isinstance(mode, list):
            ports_to_check = sorted({int(p) for p in mode if str(p).isdigit()})
        else:
            ports_to_check = list(TOP_UDP_PORTS)

        sem = asyncio.Semaphore(concurrency)
        results = await asyncio.gather(
            *[_probe_port(target, p, timeout, sem) for p in ports_to_check],
            return_exceptions=True,
        )

        responses: dict[int, str] = {}
        open_ports: list[int] = []
        for r in results:
            if isinstance(r, Exception):
                continue
            port, data = r
            if data is not None:
                open_ports.append(port)
                responses[port] = data[:64].hex()

        open_ports.sort()

        findings: list[Finding] = []

        if open_ports:
            port_lines = [
                f"  {p}/udp  open  {SERVICE_NAMES.get(p, 'unknown'):18s}  resp={responses.get(p, '')[:48]}..."
                for p in open_ports
            ]
            evidence = (
                f"UDP SCAN ({len(open_ports)} responsive / {len(ports_to_check)} probed)\n"
                f"Mode: {mode} | Target: {target} | Timeout: {timeout}s\n"
                + "\n".join(port_lines)
            )
        else:
            evidence = (
                f"UDP SCAN ({len(ports_to_check)} probed, no responses)\n"
                "Note: silent UDP ports may be open|filtered. UDP responses are not "
                "guaranteed — many services drop unknown payloads. Increase timeout or "
                "use authenticated probes for higher confidence."
            )

        findings.append(Finding(
            severity="info",
            plugin_id=META.plugin_id,
            title=f"UDP scan: {len(open_ports)} responsive ports ({mode}, {len(ports_to_check)} probed)",
            evidence=evidence,
            affected=target,
            fingerprint=stable_fingerprint(target, META.plugin_id, "summary", str(mode)),
            remediation=(
                "Review responsive UDP services and disable any not required. "
                "UDP services that respond to unauthenticated probes are common "
                "amplification vectors (DNS, NTP, SNMP, memcached, SSDP, mDNS). "
                "Apply rate-limiting, source-IP filtering, and disable recursion / "
                "monlist where supported."
            ),
        ))

        for port in open_ports:
            if port in RISKY_SERVICES:
                svc, sev, remed = RISKY_SERVICES[port]
                findings.append(Finding(
                    severity=sev,
                    plugin_id=META.plugin_id,
                    title=f"Risky UDP service exposed: {svc} on port {port}/udp",
                    description=(
                        f"UDP port {port} ({svc}) responded to a protocol probe and is "
                        "confirmed accessible from the scan source."
                    ),
                    evidence=f"port={port}/udp service={svc} response_hex={responses.get(port, '')[:80]}",
                    affected=target,
                    fingerprint=stable_fingerprint(target, META.plugin_id, "risky", port),
                    remediation=remed,
                    confidence=0.9,
                ))

        return PluginResult(
            findings=findings,
            artifacts={
                "net.open_udp_ports": open_ports,
                "net.udp_service_responses": responses,
            },
        )
