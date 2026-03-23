"""
Enhanced port scanner — Nmap-style full/top-port discovery with service detection.

Replaces the basic 14-port TCP connect scanner with configurable port ranges
(top 100, top 1000, or full 1-65535) and concurrent async scanning.

OWASP relevance: A05:2021 — Security Misconfiguration (unnecessary open ports).
"""
import asyncio
import re
import struct

from app.scanner.plugins.base import Finding, Plugin, PluginMeta, PluginResult
from app.scanner.context import stable_fingerprint

META = PluginMeta(
    plugin_id="net.port.discovery.nmap",
    name="Nmap-Style Port Scanner",
    category="network",
    provides=["net.open_ports", "net.service_banners"],
    enabled_by_default=True,   # Enabled — uses top100 mode by default (fast)
    timeout_seconds=90.0,  # External scans need more time (firewalls drop packets silently)
)

# Nmap top 1000 TCP ports (subset — top 200 most common shown here for speed)
TOP_100_PORTS = [
    7, 20, 21, 22, 23, 25, 43, 53, 67, 68, 69, 79, 80, 88, 110, 111, 113,
    119, 123, 135, 137, 138, 139, 143, 161, 162, 179, 194, 201, 389, 427,
    443, 445, 465, 500, 512, 513, 514, 515, 520, 523, 548, 554, 587, 593,
    623, 631, 636, 873, 902, 993, 995, 1025, 1080, 1099, 1194, 1433, 1434,
    1521, 1723, 1883, 2049, 2082, 2083, 2181, 2222, 2375, 2376, 3000, 3128,
    3268, 3306, 3389, 3690, 4443, 4444, 4848, 5000, 5432, 5555, 5672, 5900,
    5901, 5984, 5985, 5986, 6000, 6379, 6443, 6666, 7001, 7002, 7070, 7443,
    8000, 8008, 8009, 8080, 8081, 8088, 8443, 8888, 9000, 9090, 9091, 9200,
    9300, 9418, 9999, 10000, 11211, 15672, 27017, 27018, 28017, 50000,
]

TOP_1000_EXTRA = list(range(1, 1024)) + [
    1024, 1025, 1026, 1027, 1028, 1029, 1030, 1194, 1214, 1241, 1311, 1337,
    1433, 1434, 1521, 1701, 1720, 1723, 1755, 1883, 1900, 2000, 2049, 2082,
    2083, 2086, 2087, 2121, 2181, 2222, 2375, 2376, 2483, 2484, 3000, 3128,
    3268, 3306, 3389, 3690, 4000, 4443, 4444, 4567, 4711, 4848, 4993, 5000,
    5001, 5003, 5009, 5050, 5060, 5222, 5269, 5357, 5432, 5555, 5601, 5666,
    5672, 5683, 5800, 5900, 5901, 5938, 5984, 5985, 5986, 6000, 6001, 6379,
    6443, 6588, 6666, 6667, 6697, 7000, 7001, 7002, 7070, 7071, 7443, 7547,
    7777, 7778, 8000, 8001, 8008, 8009, 8010, 8020, 8042, 8060, 8069, 8080,
    8081, 8082, 8083, 8088, 8089, 8090, 8091, 8118, 8123, 8172, 8200, 8222,
    8333, 8443, 8444, 8500, 8649, 8834, 8880, 8888, 8899, 9000, 9001, 9002,
    9042, 9043, 9060, 9080, 9090, 9091, 9100, 9200, 9300, 9418, 9443, 9595,
    9870, 9999, 10000, 10001, 10250, 10443, 11211, 12345, 15672, 16080, 18080,
    20000, 25565, 27017, 27018, 28017, 30000, 32768, 32769, 49152, 49153,
    49154, 49155, 49156, 50000, 50070, 54321, 55553, 60000,
]

# Service name mapping for well-known ports
SERVICE_NAMES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    88: "kerberos", 110: "pop3", 111: "rpcbind", 119: "nntp", 123: "ntp",
    135: "msrpc", 137: "netbios-ns", 139: "netbios-ssn", 143: "imap",
    161: "snmp", 389: "ldap", 443: "https", 445: "microsoft-ds", 465: "smtps",
    500: "isakmp", 512: "exec", 513: "login", 514: "shell", 515: "printer",
    587: "submission", 593: "http-rpc", 636: "ldaps", 873: "rsync",
    993: "imaps", 995: "pop3s", 1080: "socks", 1099: "java-rmi",
    1433: "ms-sql", 1434: "ms-sql-m", 1521: "oracle", 1723: "pptp",
    1883: "mqtt", 2049: "nfs", 2181: "zookeeper", 2375: "docker",
    2376: "docker-tls", 3000: "grafana/node", 3128: "squid-proxy",
    3268: "ldap-gc", 3306: "mysql", 3389: "rdp", 4443: "pharos",
    4848: "glassfish", 5000: "upnp/docker", 5432: "postgresql",
    5672: "amqp", 5900: "vnc", 5984: "couchdb", 5985: "winrm",
    6000: "x11", 6379: "redis", 6443: "kubernetes-api", 7001: "weblogic",
    8000: "http-alt", 8008: "http-alt", 8009: "ajp", 8080: "http-proxy",
    8081: "http-alt", 8088: "http-alt", 8443: "https-alt", 8888: "http-alt",
    9000: "cslistener", 9090: "webmin/prometheus", 9200: "elasticsearch",
    9300: "elasticsearch", 9418: "git", 10000: "webmin", 11211: "memcached",
    15672: "rabbitmq-mgmt", 27017: "mongodb", 50000: "sap",
}

# Known risky services that should generate warnings
RISKY_SERVICES = {
    23: ("telnet", "critical", "Telnet transmits credentials in plaintext. Disable telnet and use SSH instead."),
    21: ("ftp", "high", "FTP transmits credentials in plaintext. Use SFTP or FTPS instead."),
    512: ("rexec", "high", "Remote execution service is running. Disable if not needed."),
    513: ("rlogin", "high", "rlogin allows remote login without encryption. Disable and use SSH."),
    514: ("rsh", "high", "Remote shell (rsh) has no encryption. Disable and use SSH."),
    161: ("snmp", "medium", "SNMP is exposed. Ensure SNMPv3 with authentication is used, not v1/v2c."),
    445: ("smb", "medium", "SMB port exposed. Ensure SMBv1 is disabled and access is restricted."),
    6379: ("redis", "high", "Redis is exposed. Bind to localhost only and enable AUTH."),
    11211: ("memcached", "high", "Memcached exposed. Bind to localhost to prevent amplification attacks."),
    9200: ("elasticsearch", "high", "Elasticsearch exposed. Enable X-Pack security and restrict access."),
    27017: ("mongodb", "high", "MongoDB exposed. Enable authentication and bind to localhost."),
    2375: ("docker", "critical", "Docker API exposed without TLS! Attacker can run arbitrary containers. Use TLS (port 2376)."),
    5900: ("vnc", "high", "VNC exposed. Use SSH tunneling and strong authentication."),
    3389: ("rdp", "medium", "RDP exposed. Enable NLA, use strong passwords, consider VPN-only access."),
    1433: ("mssql", "medium", "MS SQL Server exposed. Restrict to trusted IPs and use strong SA passwords."),
    3306: ("mysql", "medium", "MySQL exposed. Bind to localhost or restrict to trusted IPs."),
    5432: ("postgresql", "medium", "PostgreSQL exposed. Review pg_hba.conf and restrict access."),
}


async def _tcp_connect(host: str, port: int, timeout: float) -> bool:
    """Attempt TCP connection. Returns True if port is open."""
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False


async def _grab_banner(host: str, port: int, timeout: float) -> str:
    """Try to grab a service banner from an open port."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        # Some services send a banner immediately
        try:
            data = await asyncio.wait_for(reader.read(512), timeout=2.0)
        except asyncio.TimeoutError:
            # Try sending a probe for HTTP-like services
            writer.write(b"HEAD / HTTP/1.0\r\nHost: probe\r\n\r\n")
            await writer.drain()
            try:
                data = await asyncio.wait_for(reader.read(512), timeout=2.0)
            except asyncio.TimeoutError:
                data = b""
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return data.decode("utf-8", errors="replace").strip()[:256]
    except Exception:
        return ""


class Check(Plugin):
    async def run(self, target: str, ctx) -> PluginResult:
        target_raw = ctx.get("target_raw", target)
        scan_type = ctx.get("scan_type", "internal")
        options = ctx.get("profile_options", {})
        findings: list[Finding] = []

        # Determine scan mode from profile options
        nmap_mode = options.get("nmap", {}).get("mode", "top100")
        # top100 / top1000 / full / quick
        per_port_timeout = 2.0 if scan_type == "internal" else 5.0

        # If target is URL, extract implied ports + do limited scan
        if re.match(r"^https?://", target_raw, re.I):
            scheme = "https" if "https" in target_raw.lower() else "http"
            implied = [443, 80] if scheme == "https" else [80, 443]
            # Also check common alt ports for web targets
            extra_web = [8080, 8443, 8000, 8888, 3000, 9090]
            ports_to_check = list(set(implied + extra_web))
        elif nmap_mode == "full":
            ports_to_check = list(range(1, 65536))
            per_port_timeout = 1.5
        elif nmap_mode == "top1000":
            ports_to_check = sorted(set(TOP_1000_EXTRA))
        else:
            ports_to_check = TOP_100_PORTS

        # Concurrent scanning with semaphore to avoid overwhelming target
        concurrency = 200 if nmap_mode == "full" else 50
        sem = asyncio.Semaphore(concurrency)
        open_ports: list[int] = []

        async def check_port(port):
            async with sem:
                if await _tcp_connect(target, port, per_port_timeout):
                    open_ports.append(port)

        # Run all port checks
        await asyncio.gather(
            *[check_port(p) for p in ports_to_check],
            return_exceptions=True,
        )
        open_ports.sort()

        # Grab banners from open ports (max 30 to save time)
        banners: dict[int, str] = {}
        banner_ports = open_ports[:30]
        if banner_ports:
            sem_banner = asyncio.Semaphore(10)

            async def grab(port):
                async with sem_banner:
                    b = await _grab_banner(target, port, 3.0)
                    if b:
                        banners[port] = b

            await asyncio.gather(
                *[grab(p) for p in banner_ports],
                return_exceptions=True,
            )

        # Build port table evidence
        port_lines = []
        for p in open_ports:
            svc = SERVICE_NAMES.get(p, "unknown")
            banner = banners.get(p, "")
            if banner:
                # Extract service version from banner
                banner_short = banner.replace("\n", " ").replace("\r", " ")[:80]
                port_lines.append(f"  {p}/tcp  open  {svc:20s}  {banner_short}")
            else:
                port_lines.append(f"  {p}/tcp  open  {svc}")

        evidence_text = (
            f"PORT SCAN RESULTS ({len(open_ports)} open / {len(ports_to_check)} scanned)\n"
            f"Mode: {nmap_mode} | Target: {target}\n"
            + "\n".join(port_lines)
        )

        # Main discovery finding
        findings.append(Finding(
            severity="info",
            plugin_id=META.plugin_id,
            title=f"Port scan: {len(open_ports)} open ports ({nmap_mode} mode, {len(ports_to_check)} checked)",
            evidence=evidence_text,
            affected=target,
            fingerprint=stable_fingerprint(target, META.plugin_id, "summary"),
            remediation=(
                "Review all open ports and close unnecessary services. "
                "Use firewall rules (iptables/nftables/Security Groups) to restrict access. "
                "Only expose ports required for the application to function."
            ),
        ))

        # Risky service findings
        for port in open_ports:
            if port in RISKY_SERVICES:
                svc_name, sev, remed = RISKY_SERVICES[port]
                banner = banners.get(port, "")
                findings.append(Finding(
                    severity=sev,
                    plugin_id=META.plugin_id,
                    title=f"Risky service exposed: {svc_name} on port {port}",
                    description=(
                        f"Port {port} ({svc_name}) is open and accessible. "
                        f"This service is commonly targeted by attackers."
                    ),
                    evidence=f"port={port} service={svc_name} banner={banner[:100]}",
                    affected=target,
                    fingerprint=stable_fingerprint(target, META.plugin_id, "risky", port),
                    remediation=remed,
                    confidence=0.95,
                ))

        # Too many open ports warning
        if len(open_ports) > 20:
            findings.append(Finding(
                severity="medium",
                plugin_id=META.plugin_id,
                title=f"Excessive open ports: {len(open_ports)} services exposed",
                description=(
                    f"The target has {len(open_ports)} open ports, which increases the attack surface. "
                    "Each open port is a potential entry point for attackers."
                ),
                evidence=f"open_port_count={len(open_ports)} ports={open_ports[:20]}...",
                affected=target,
                fingerprint=stable_fingerprint(target, META.plugin_id, "excessive_ports"),
                remediation=(
                    "Reduce the attack surface by closing unnecessary ports. "
                    "Implement a default-deny firewall policy and only allow "
                    "required services. Use network segmentation."
                ),
            ))

        return PluginResult(
            findings=findings,
            artifacts={
                "net.open_ports": open_ports,
                "net.service_banners": banners,
            },
        )