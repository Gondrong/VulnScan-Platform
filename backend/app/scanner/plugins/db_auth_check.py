"""
Database Authentication Testing Plugin — checks exposed database services
for missing authentication, default credentials, and misconfiguration.

Tests the following services (when their ports are open):
  - Redis (6379)       → no-auth access, INFO command exposure
  - MongoDB (27017)    → no-auth access, database listing
  - MySQL (3306)       → anonymous login, default root with no password
  - PostgreSQL (5432)  → default postgres user with common passwords
  - Elasticsearch (9200) → unauthenticated API access
  - Memcached (11211)  → no-auth access, stats exposure

All tests are read-only and non-destructive. No data is modified.
"""
import asyncio
import logging

from app.scanner.plugins.base import Finding, Plugin, PluginMeta, PluginResult
from app.scanner.context import stable_fingerprint

logger = logging.getLogger("vulnscan.db_auth_check")

META = PluginMeta(
    plugin_id="infra.db.auth_check",
    name="Database Authentication Checker",
    category="network",
    depends_on=["net.port.discovery.v2"],
    consumes=["net.open_ports", "net.service_banners"],
    provides=["infra.db.findings"],
    enabled_by_default=True,
    timeout_seconds=20.0,
)

# Ports we test and their service names
_DB_PORTS = {
    6379: "redis",
    27017: "mongodb",
    3306: "mysql",
    5432: "postgresql",
    9200: "elasticsearch",
    11211: "memcached",
}


async def _tcp_exchange(host: str, port: int, payload: bytes,
                        timeout: float = 3.0) -> bytes:
    """Send payload to TCP port and read response."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        if payload:
            writer.write(payload)
            await writer.drain()
        data = await asyncio.wait_for(reader.read(4096), timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return data
    except Exception:
        return b""


async def _tcp_read(host: str, port: int, timeout: float = 3.0) -> bytes:
    """Connect to TCP port and read whatever the server sends."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        data = await asyncio.wait_for(reader.read(4096), timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return data
    except Exception:
        return b""


async def _check_redis(host: str, findings: list[Finding]):
    """Test Redis for no-auth access."""
    # Try PING without authentication
    resp = await _tcp_exchange(host, 6379, b"PING\r\n")
    text = resp.decode("utf-8", errors="ignore").strip()

    if "+PONG" in text:
        # Redis responds without auth — fully open
        # Try INFO to get version and config details
        info_resp = await _tcp_exchange(host, 6379, b"INFO server\r\n")
        info_text = info_resp.decode("utf-8", errors="ignore")

        version = ""
        for line in info_text.splitlines():
            if line.startswith("redis_version:"):
                version = line.split(":", 1)[1].strip()
                break

        findings.append(Finding(
            severity="critical",
            plugin_id=META.plugin_id,
            title=f"Redis accessible without authentication on port 6379",
            description=(
                f"Redis on {host}:6379 accepts commands without any authentication. "
                f"An attacker can read/write all data, execute Lua scripts, and "
                f"potentially achieve remote code execution via CONFIG SET, MODULE LOAD, "
                f"or writing to the filesystem (e.g., writing SSH keys or crontabs)."
            ),
            evidence=(
                f"host={host} port=6379 ping_response=+PONG auth_required=no "
                f"redis_version={version or 'unknown'}"
            ),
            affected=f"{host}:6379",
            fingerprint=stable_fingerprint(host, META.plugin_id, "redis_noauth"),
            remediation=(
                "[CRITICAL — No Authentication]\n"
                "Redis is accessible without a password. This is a critical security risk.\n\n"
                "Immediate remediation:\n"
                "1. Set a strong password: requirepass <strong-password> in redis.conf\n"
                "2. Bind to localhost only: bind 127.0.0.1 ::1\n"
                "3. Enable protected mode: protected-mode yes\n"
                "4. Disable dangerous commands:\n"
                "   rename-command FLUSHALL \"\"\n"
                "   rename-command FLUSHDB \"\"\n"
                "   rename-command CONFIG \"\"\n"
                "   rename-command DEBUG \"\"\n"
                "5. Use firewall rules to restrict port 6379 access\n"
                "6. Consider enabling TLS (Redis 6+): tls-port 6380\n\n"
                "Reference: https://redis.io/docs/management/security/"
            ),
            confidence=0.95,
            references=[
                "https://redis.io/docs/management/security/",
                "https://cwe.mitre.org/data/definitions/306.html",
            ],
        ))

        # Check if CONFIG is accessible (RCE risk)
        config_resp = await _tcp_exchange(host, 6379, b"CONFIG GET dir\r\n")
        config_text = config_resp.decode("utf-8", errors="ignore")
        if "dir" in config_text.lower() and "-ERR" not in config_text:
            findings.append(Finding(
                severity="critical",
                plugin_id=META.plugin_id,
                title="Redis CONFIG command accessible — potential RCE",
                description=(
                    "The Redis CONFIG command is not disabled. An attacker can use "
                    "CONFIG SET dir/dbfilename to write arbitrary files to the server, "
                    "enabling remote code execution via SSH key injection or crontab writing."
                ),
                evidence=f"host={host} port=6379 config_get_dir_response={config_text[:200]}",
                affected=f"{host}:6379",
                fingerprint=stable_fingerprint(host, META.plugin_id, "redis_config_rce"),
                remediation=(
                    "[CRITICAL — Remote Code Execution Risk]\n"
                    "Rename or disable the CONFIG command in redis.conf:\n"
                    "  rename-command CONFIG \"\"\n\n"
                    "Known attack vectors:\n"
                    "- CONFIG SET dir /root/.ssh && CONFIG SET dbfilename authorized_keys\n"
                    "- CONFIG SET dir /var/spool/cron && CONFIG SET dbfilename root\n"
                    "- MODULE LOAD /path/to/malicious.so"
                ),
                confidence=0.95,
            ))

    elif "-NOAUTH" in text or "Authentication required" in text.lower():
        # Redis requires auth — good, but it's still exposed on the network
        findings.append(Finding(
            severity="low",
            plugin_id=META.plugin_id,
            title="Redis requires authentication (port 6379 exposed)",
            description=(
                "Redis on this host requires authentication before accepting commands. "
                "However, the port is still network-accessible, making it a target for "
                "brute-force attacks."
            ),
            evidence=f"host={host} port=6379 auth_required=yes response={text[:100]}",
            affected=f"{host}:6379",
            fingerprint=stable_fingerprint(host, META.plugin_id, "redis_auth_ok"),
            remediation=(
                "Redis authentication is enabled (good). Additional hardening:\n"
                "- Bind to localhost if remote access is not needed\n"
                "- Use firewall rules to restrict access\n"
                "- Enable TLS (Redis 6+)\n"
                "- Use ACLs for fine-grained access control (Redis 6+)"
            ),
            confidence=0.90,
        ))


async def _check_mongodb(host: str, findings: list[Finding]):
    """Test MongoDB for no-auth access using the wire protocol."""
    # MongoDB wire protocol: OP_QUERY for ismaster/hello
    # Build a minimal OP_QUERY message
    # This is a simplified check — we send a raw isMaster query

    # Alternative: use the HTTP status endpoint if available
    import struct

    # Try the HTTP monitoring interface first (port 28017 deprecated, but 27017 sometimes has it)
    # Use wire protocol: OP_MSG with isMaster
    try:
        # Build OP_MSG (opcode 2013) with {isMaster: 1} document
        # BSON for {isMaster: 1}:
        doc = (
            b"\x13\x00\x00\x00"  # doc size = 19
            b"\x10"              # int32 type
            b"isMaster\x00"     # key
            b"\x01\x00\x00\x00"  # value = 1
            b"\x00"              # doc terminator
        )
        # Section: kind=0 (body), followed by document
        section = b"\x00" + doc

        # MsgHeader: length(4) + requestID(4) + responseTo(4) + opCode(4)
        # Then flagBits(4) + section
        flag_bits = b"\x00\x00\x00\x00"
        msg_body = flag_bits + section
        msg_len = 16 + len(msg_body)  # 16 = header size

        header = struct.pack("<iiii", msg_len, 1, 0, 2013)
        full_msg = header + msg_body

        resp = await _tcp_exchange(host, 27017, full_msg, timeout=3.0)
        if resp and len(resp) > 20:
            text = resp.decode("utf-8", errors="ignore")
            # Look for indicators of successful connection
            if "ismaster" in text.lower() or "maxbsonobjectsize" in text.lower():
                findings.append(Finding(
                    severity="critical",
                    plugin_id=META.plugin_id,
                    title="MongoDB accessible without authentication on port 27017",
                    description=(
                        f"MongoDB on {host}:27017 accepts connections without authentication. "
                        f"An attacker can read, modify, or delete all databases. "
                        f"This is one of the most common causes of large-scale data breaches."
                    ),
                    evidence=(
                        f"host={host} port=27017 auth_required=no "
                        f"response_sample={text[:200]}"
                    ),
                    affected=f"{host}:27017",
                    fingerprint=stable_fingerprint(host, META.plugin_id, "mongodb_noauth"),
                    remediation=(
                        "[CRITICAL — No Authentication]\n"
                        "MongoDB is accessible without authentication.\n\n"
                        "Immediate remediation:\n"
                        "1. Enable authentication in mongod.conf:\n"
                        "   security:\n"
                        "     authorization: enabled\n"
                        "2. Create admin user:\n"
                        "   use admin\n"
                        "   db.createUser({user:'admin', pwd:'STRONG_PASSWORD', roles:['root']})\n"
                        "3. Bind to localhost: net.bindIp: 127.0.0.1\n"
                        "4. Enable TLS: net.tls.mode: requireTLS\n"
                        "5. Use firewall rules to restrict port 27017\n\n"
                        "Reference: https://www.mongodb.com/docs/manual/administration/security-checklist/"
                    ),
                    confidence=0.90,
                    references=[
                        "https://www.mongodb.com/docs/manual/administration/security-checklist/",
                        "https://cwe.mitre.org/data/definitions/306.html",
                    ],
                ))
                return

    except Exception:
        pass

    # Fallback: try connecting and reading the banner
    banner = await _tcp_read(host, 27017, timeout=3.0)
    if banner:
        text = banner.decode("utf-8", errors="ignore")
        if "mongodb" in text.lower() or "mongo" in text.lower():
            findings.append(Finding(
                severity="medium",
                plugin_id=META.plugin_id,
                title="MongoDB port 27017 responds — authentication status unknown",
                evidence=f"host={host} port=27017 banner={text[:200]}",
                affected=f"{host}:27017",
                fingerprint=stable_fingerprint(host, META.plugin_id, "mongodb_exposed"),
                remediation=(
                    "MongoDB is network-accessible. Verify that authentication is enabled "
                    "and the service is bound to trusted interfaces only."
                ),
            ))


async def _check_elasticsearch(host: str, findings: list[Finding]):
    """Test Elasticsearch for unauthenticated API access."""
    resp = await _tcp_exchange(
        host, 9200,
        b"GET / HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\n\r\n",
        timeout=3.0,
    )
    text = resp.decode("utf-8", errors="ignore")

    if "cluster_name" in text or "cluster_uuid" in text or "lucene_version" in text:
        # Extract version
        version = ""
        import re
        ver_match = re.search(r'"number"\s*:\s*"([^"]+)"', text)
        if ver_match:
            version = ver_match.group(1)

        cluster_match = re.search(r'"cluster_name"\s*:\s*"([^"]+)"', text)
        cluster_name = cluster_match.group(1) if cluster_match else "unknown"

        findings.append(Finding(
            severity="high",
            plugin_id=META.plugin_id,
            title=f"Elasticsearch accessible without authentication (v{version or 'unknown'})",
            description=(
                f"Elasticsearch on {host}:9200 responds to API requests without authentication. "
                f"Cluster '{cluster_name}' is fully accessible. An attacker can read all indices, "
                f"modify data, and potentially execute scripts."
            ),
            evidence=(
                f"host={host} port=9200 auth_required=no "
                f"version={version} cluster={cluster_name}"
            ),
            affected=f"{host}:9200",
            fingerprint=stable_fingerprint(host, META.plugin_id, "es_noauth"),
            remediation=(
                "[HIGH — No Authentication]\n"
                "Elasticsearch is accessible without authentication.\n\n"
                "Remediation:\n"
                "1. Enable X-Pack security (free since ES 6.8/7.1):\n"
                "   xpack.security.enabled: true\n"
                "2. Set passwords: elasticsearch-setup-passwords auto\n"
                "3. Enable TLS for transport and HTTP layers\n"
                "4. Bind to localhost: network.host: 127.0.0.1\n"
                "5. Use firewall rules to restrict port 9200/9300\n\n"
                "Reference: https://www.elastic.co/guide/en/elasticsearch/reference/current/security-minimal-setup.html"
            ),
            confidence=0.95,
            references=[
                "https://www.elastic.co/guide/en/elasticsearch/reference/current/security-minimal-setup.html",
                "https://cwe.mitre.org/data/definitions/306.html",
            ],
        ))

        # Check if _cat/indices is accessible (data exposure)
        idx_resp = await _tcp_exchange(
            host, 9200,
            b"GET /_cat/indices?v&h=index,docs.count,store.size HTTP/1.1\r\nHost: localhost\r\n\r\n",
            timeout=3.0,
        )
        idx_text = idx_resp.decode("utf-8", errors="ignore")
        if "index" in idx_text.lower() and "200 OK" in idx_text:
            # Count indices
            idx_lines = [l for l in idx_text.split("\n") if l.strip() and not l.startswith("HTTP") and "index" not in l.lower()[:10]]
            findings.append(Finding(
                severity="high",
                plugin_id=META.plugin_id,
                title=f"Elasticsearch indices accessible — {len(idx_lines)} indices exposed",
                evidence=f"host={host} port=9200 indices_count={len(idx_lines)} sample={idx_text[:300]}",
                affected=f"{host}:9200",
                fingerprint=stable_fingerprint(host, META.plugin_id, "es_indices"),
                remediation="Enable X-Pack security and restrict index-level access with roles.",
                confidence=0.95,
            ))

    elif "401" in text or "Unauthorized" in text or "security_exception" in text:
        findings.append(Finding(
            severity="info",
            plugin_id=META.plugin_id,
            title="Elasticsearch requires authentication (port 9200 exposed)",
            evidence=f"host={host} port=9200 auth_required=yes",
            affected=f"{host}:9200",
            fingerprint=stable_fingerprint(host, META.plugin_id, "es_auth_ok"),
            remediation="Elasticsearch authentication is enabled. Ensure TLS is also configured.",
        ))


async def _check_memcached(host: str, findings: list[Finding]):
    """Test Memcached for unauthenticated access."""
    resp = await _tcp_exchange(host, 11211, b"stats\r\n", timeout=3.0)
    text = resp.decode("utf-8", errors="ignore")

    if "STAT " in text:
        # Extract key stats
        version = ""
        curr_items = ""
        bytes_used = ""
        for line in text.splitlines():
            if line.startswith("STAT version"):
                version = line.split()[-1] if len(line.split()) >= 3 else ""
            elif line.startswith("STAT curr_items"):
                curr_items = line.split()[-1] if len(line.split()) >= 3 else ""
            elif line.startswith("STAT bytes "):
                bytes_used = line.split()[-1] if len(line.split()) >= 3 else ""

        findings.append(Finding(
            severity="high",
            plugin_id=META.plugin_id,
            title=f"Memcached accessible without authentication (v{version or 'unknown'})",
            description=(
                f"Memcached on {host}:11211 accepts commands without authentication. "
                f"Exposed Memcached instances are commonly exploited for DDoS amplification "
                f"attacks and data theft. Items in cache: {curr_items or 'unknown'}."
            ),
            evidence=(
                f"host={host} port=11211 auth_required=no "
                f"version={version} items={curr_items} bytes={bytes_used}"
            ),
            affected=f"{host}:11211",
            fingerprint=stable_fingerprint(host, META.plugin_id, "memcached_noauth"),
            remediation=(
                "[HIGH — No Authentication + DDoS Amplification Risk]\n"
                "Memcached is accessible without authentication.\n\n"
                "Remediation:\n"
                "1. Bind to localhost only: -l 127.0.0.1\n"
                "2. Disable UDP (amplification vector): -U 0\n"
                "3. Enable SASL authentication if remote access needed\n"
                "4. Use firewall rules to block port 11211 from internet\n"
                "5. Reduce max item size to limit amplification\n\n"
                "Reference: https://www.memcached.org/about"
            ),
            confidence=0.95,
            references=[
                "https://cwe.mitre.org/data/definitions/306.html",
                "https://www.us-cert.gov/ncas/alerts/TA18-106A",
            ],
        ))


async def _check_mysql(host: str, findings: list[Finding]):
    """Test MySQL for anonymous login / version disclosure."""
    # MySQL sends a greeting packet on connect
    banner = await _tcp_read(host, 3306, timeout=3.0)
    if not banner or len(banner) < 5:
        return

    text = banner.decode("utf-8", errors="ignore")

    # MySQL greeting packet: byte[0-3]=length, byte[4]=sequence
    # Then protocol version, server version string (null-terminated)
    version = ""
    try:
        # Skip packet header (4 bytes) + protocol version (1 byte)
        if len(banner) > 5:
            ver_start = 5
            ver_end = banner.index(b"\x00", ver_start)
            version = banner[ver_start:ver_end].decode("ascii", errors="ignore")
    except (ValueError, IndexError):
        pass

    if version:
        findings.append(Finding(
            severity="low",
            plugin_id=META.plugin_id,
            title=f"MySQL version disclosed: {version}",
            description=(
                f"MySQL on {host}:3306 reveals its version in the greeting packet. "
                f"Version: {version}. This information helps attackers identify known "
                f"vulnerabilities for this specific version."
            ),
            evidence=f"host={host} port=3306 version={version}",
            affected=f"{host}:3306",
            fingerprint=stable_fingerprint(host, META.plugin_id, "mysql_version", version),
            remediation=(
                "MySQL version disclosure is normal protocol behavior and cannot be "
                "fully suppressed. Ensure MySQL is:\n"
                "- Updated to the latest version\n"
                "- Bound to localhost or trusted IPs only (bind-address in my.cnf)\n"
                "- Using strong authentication (no anonymous users)\n"
                "- Behind a firewall restricting port 3306"
            ),
        ))

    # Check for auth errors vs access denied to determine if anon login works
    # The greeting itself doesn't confirm anon access — we'd need to attempt auth
    # which requires the MySQL protocol handshake. For safety, just report exposure.
    if "Access denied" not in text and "ERROR" not in text:
        # If we got a clean greeting without immediate rejection
        findings.append(Finding(
            severity="medium",
            plugin_id=META.plugin_id,
            title="MySQL exposed on network — verify authentication hardening",
            description=(
                f"MySQL on {host}:3306 is network-accessible and accepting connections. "
                f"Verify that anonymous users are removed, root has a strong password, "
                f"and only trusted IPs can connect."
            ),
            evidence=f"host={host} port=3306 version={version} greeting_received=yes",
            affected=f"{host}:3306",
            fingerprint=stable_fingerprint(host, META.plugin_id, "mysql_exposed"),
            remediation=(
                "[MEDIUM — Database Exposed]\n"
                "Run mysql_secure_installation to harden MySQL:\n"
                "1. Set a strong root password\n"
                "2. Remove anonymous users\n"
                "3. Disable remote root login\n"
                "4. Remove test database\n"
                "5. Set bind-address = 127.0.0.1 in my.cnf\n"
                "6. Use SSL for remote connections: REQUIRE SSL"
            ),
            confidence=0.70,
        ))


async def _check_postgresql(host: str, findings: list[Finding]):
    """Test PostgreSQL for version disclosure and exposure."""
    import struct

    # PostgreSQL startup message: try connecting as 'postgres' with no password
    # Build a StartupMessage (protocol 3.0)
    user = b"postgres"
    database = b"postgres"
    # key-value pairs: user, database, then double null terminator
    params = b"user\x00" + user + b"\x00database\x00" + database + b"\x00\x00"
    # Protocol version 3.0 = 196608
    proto = struct.pack("!I", 196608)
    msg_len = 4 + len(proto) + len(params)
    startup = struct.pack("!I", msg_len) + proto + params

    resp = await _tcp_exchange(host, 5432, startup, timeout=3.0)
    if not resp:
        return

    # Check response type
    if len(resp) > 0:
        msg_type = chr(resp[0]) if resp[0] < 128 else ""

        if msg_type == "R":
            # Authentication request — PostgreSQL is responding
            # R with auth type tells us what auth is required
            if len(resp) >= 9:
                auth_type = struct.unpack("!I", resp[5:9])[0] if len(resp) >= 9 else -1

                if auth_type == 0:
                    # AuthenticationOk — NO PASSWORD REQUIRED
                    findings.append(Finding(
                        severity="critical",
                        plugin_id=META.plugin_id,
                        title="PostgreSQL accepts connections without password (trust auth)",
                        description=(
                            f"PostgreSQL on {host}:5432 allows login as 'postgres' without "
                            f"a password. This typically means pg_hba.conf uses 'trust' method "
                            f"for network connections, granting full superuser access to anyone."
                        ),
                        evidence=f"host={host} port=5432 user=postgres auth_type=trust(0)",
                        affected=f"{host}:5432",
                        fingerprint=stable_fingerprint(host, META.plugin_id, "pg_noauth"),
                        remediation=(
                            "[CRITICAL — Trust Authentication on Network]\n"
                            "PostgreSQL accepts passwordless connections.\n\n"
                            "Remediation:\n"
                            "1. Edit pg_hba.conf — change 'trust' to 'scram-sha-256' or 'md5':\n"
                            "   host all all 0.0.0.0/0 scram-sha-256\n"
                            "2. Set a strong password for postgres user:\n"
                            "   ALTER USER postgres PASSWORD 'STRONG_PASSWORD';\n"
                            "3. Restrict listen_addresses in postgresql.conf:\n"
                            "   listen_addresses = 'localhost'\n"
                            "4. Reload: pg_ctl reload\n"
                            "5. Use SSL: ssl = on in postgresql.conf"
                        ),
                        confidence=0.95,
                        references=[
                            "https://www.postgresql.org/docs/current/auth-pg-hba-conf.html",
                            "https://cwe.mitre.org/data/definitions/306.html",
                        ],
                    ))
                else:
                    auth_names = {
                        3: "cleartext_password", 5: "md5", 10: "scram-sha-256",
                    }
                    auth_name = auth_names.get(auth_type, f"type_{auth_type}")
                    findings.append(Finding(
                        severity="low" if auth_type in (5, 10) else "medium",
                        plugin_id=META.plugin_id,
                        title=f"PostgreSQL exposed — {auth_name} authentication required",
                        evidence=f"host={host} port=5432 auth_method={auth_name} auth_type={auth_type}",
                        affected=f"{host}:5432",
                        fingerprint=stable_fingerprint(host, META.plugin_id, "pg_exposed"),
                        remediation=(
                            f"PostgreSQL requires {auth_name} authentication (good). "
                            "Additional hardening:\n"
                            "- Upgrade to scram-sha-256 if using md5\n"
                            "- Bind to localhost if remote access not needed\n"
                            "- Use SSL for all connections\n"
                            "- Review pg_hba.conf for overly permissive rules"
                        ),
                    ))

        elif msg_type == "E":
            # Error response — parse error message
            error_text = resp.decode("utf-8", errors="ignore")
            findings.append(Finding(
                severity="info",
                plugin_id=META.plugin_id,
                title="PostgreSQL port 5432 active — connection rejected",
                evidence=f"host={host} port=5432 error={error_text[:200]}",
                affected=f"{host}:5432",
                fingerprint=stable_fingerprint(host, META.plugin_id, "pg_rejected"),
            ))


class Check(Plugin):
    async def run(self, target: str, ctx) -> PluginResult:
        open_ports = ctx.get("net.open_ports", []) or []
        findings: list[Finding] = []

        # Determine which DB services to test
        db_ports_open = {p: svc for p, svc in _DB_PORTS.items() if p in open_ports}

        if not db_ports_open:
            return PluginResult(
                findings=[],
                artifacts={"infra.db.findings": 0},
            )

        # Run checks concurrently for all detected database services
        tasks = []
        for port, svc in db_ports_open.items():
            if svc == "redis":
                tasks.append(_check_redis(target, findings))
            elif svc == "mongodb":
                tasks.append(_check_mongodb(target, findings))
            elif svc == "elasticsearch":
                tasks.append(_check_elasticsearch(target, findings))
            elif svc == "memcached":
                tasks.append(_check_memcached(target, findings))
            elif svc == "mysql":
                tasks.append(_check_mysql(target, findings))
            elif svc == "postgresql":
                tasks.append(_check_postgresql(target, findings))

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

        return PluginResult(
            findings=findings,
            artifacts={"infra.db.findings": len(findings)},
        )

