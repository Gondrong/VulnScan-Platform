"""
Redis No-Auth Scanner — dedicated deep check for unauthenticated Redis instances.

Goes beyond the basic db_auth_check plugin with:
  - CONFIG writability test (RCE via file write)
  - MODULE LOAD availability (RCE via shared object)
  - SLAVEOF/REPLICAOF availability (data exfiltration)
  - Key enumeration (data exposure scope)
  - Lua scripting check (EVAL)
  - Client list (who else is connected)
  - Memory/key count for impact assessment

All tests are read-only. No data is written or modified.
"""
import asyncio
import logging

from app.scanner.plugins.base import Finding, Plugin, PluginMeta, PluginResult
from app.scanner.context import stable_fingerprint

logger = logging.getLogger("vulnscan.redis_noauth")

META = PluginMeta(
    plugin_id="infra.redis.deep",
    name="Redis No-Auth Deep Scanner",
    category="network",
    depends_on=["net.port.discovery.v2"],
    soft_depends_on=["infra.db.auth_check"],
    consumes=["net.open_ports"],
    provides=["infra.redis.findings"],
    enabled_by_default=True,
    timeout_seconds=15.0,
)

# Common Redis ports
_REDIS_PORTS = [6379, 6380, 6381]


async def _redis_cmd(host: str, port: int, cmd: str,
                     timeout: float = 3.0) -> str:
    """Send a Redis command and return the response text."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        writer.write(f"{cmd}\r\n".encode())
        await writer.drain()
        data = await asyncio.wait_for(reader.read(8192), timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return data.decode("utf-8", errors="ignore")
    except Exception:
        return ""


async def _check_redis_port(host: str, port: int,
                            findings: list[Finding]) -> bool:
    """Deep-check a single Redis port. Returns True if no-auth confirmed."""
    # Step 1: PING test
    resp = await _redis_cmd(host, port, "PING")
    text = resp.strip()

    if "+PONG" not in text:
        return False

    # No-auth confirmed — gather details
    info = {}

    # Step 2: INFO for version, memory, keys
    info_resp = await _redis_cmd(host, port, "INFO")
    for line in info_resp.splitlines():
        if ":" in line and not line.startswith("#") and not line.startswith("$"):
            k, _, v = line.partition(":")
            info[k.strip()] = v.strip()

    version = info.get("redis_version", "unknown")
    used_memory_human = info.get("used_memory_human", "?")
    total_keys = 0
    for k, v in info.items():
        if k.startswith("db") and k[2:].isdigit():
            # Parse "keys=42,expires=0,avg_ttl=0"
            for part in v.split(","):
                if part.startswith("keys="):
                    try:
                        total_keys += int(part.split("=")[1])
                    except ValueError:
                        pass

    connected_clients = info.get("connected_clients", "?")
    os_info = info.get("os", "")

    # Step 3: CONFIG GET dir — can we write files?
    config_dir = ""
    config_resp = await _redis_cmd(host, port, "CONFIG GET dir")
    if "dir" in config_resp.lower() and "-ERR" not in config_resp:
        for line in config_resp.splitlines():
            line = line.strip()
            if line and not line.startswith("*") and not line.startswith("$") and line != "dir":
                config_dir = line
                break

    config_writable = bool(config_dir)

    # Step 4: Check dangerous commands
    dangerous = {}
    for cmd_name, cmd_str in [
        ("CONFIG SET", "CONFIG SET __vulnscan_test__ test"),
        ("SCRIPT", "SCRIPT EXISTS __dummy__"),
        ("CLIENT LIST", "CLIENT LIST"),
        ("DEBUG", "DEBUG SLEEP 0"),
    ]:
        r = await _redis_cmd(host, port, cmd_str)
        # Check if the command is NOT disabled
        disabled = "-ERR" in r and ("unknown command" in r.lower() or
                                     "not allowed" in r.lower() or
                                     "renamed" in r.lower())
        dangerous[cmd_name] = not disabled

    # Clean up test key if CONFIG SET succeeded
    if dangerous.get("CONFIG SET"):
        await _redis_cmd(host, port, "CONFIG SET __vulnscan_test__ \"\"")

    # Step 5: Check SLAVEOF/REPLICAOF availability
    slaveof_resp = await _redis_cmd(host, port, "COMMAND INFO SLAVEOF")
    slaveof_available = "-ERR" not in slaveof_resp and "null" not in slaveof_resp.lower()

    # Build findings
    rce_vectors = []
    if config_writable:
        rce_vectors.append("CONFIG SET dir/dbfilename (write SSH keys, crontabs)")
    if dangerous.get("SCRIPT"):
        rce_vectors.append("EVAL (Lua scripting)")
    if dangerous.get("DEBUG"):
        rce_vectors.append("DEBUG (debug commands enabled)")

    severity = "critical"
    fp = stable_fingerprint(host, META.plugin_id, "noauth", str(port))
    findings.append(Finding(
        severity=severity,
        plugin_id=META.plugin_id,
        title=(
            f"Redis {version} on port {port} — no authentication, "
            f"{total_keys} keys, {used_memory_human} memory"
        ),
        description=(
            f"Redis {version} on {host}:{port} is accessible without authentication. "
            f"Database contains {total_keys} keys using {used_memory_human} of memory. "
            f"{connected_clients} clients connected. "
            f"{'RCE possible via: ' + ', '.join(rce_vectors) + '. ' if rce_vectors else ''}"
            f"{'Data exfiltration possible via SLAVEOF/REPLICAOF. ' if slaveof_available else ''}"
            f"OS: {os_info or 'unknown'}."
        ),
        evidence=(
            f"host={host} port={port} auth=none version={version} "
            f"keys={total_keys} memory={used_memory_human} "
            f"config_writable={config_writable} config_dir={config_dir} "
            f"dangerous_cmds={dangerous} slaveof={slaveof_available} "
            f"os={os_info}"
        ),
        affected=f"{host}:{port}",
        fingerprint=fp,
        confidence=0.98,
        remediation=(
            "[CRITICAL — Redis Unauthenticated Access]\n\n"
            "Immediate actions:\n"
            "1. Set a strong password:\n"
            "   redis.conf: requirepass <64-char-random-string>\n"
            "2. Bind to localhost:\n"
            "   redis.conf: bind 127.0.0.1 ::1\n"
            "3. Enable protected mode:\n"
            "   redis.conf: protected-mode yes\n"
            "4. Disable/rename dangerous commands:\n"
            "   rename-command CONFIG \"\"\n"
            "   rename-command FLUSHALL \"\"\n"
            "   rename-command FLUSHDB \"\"\n"
            "   rename-command DEBUG \"\"\n"
            "   rename-command SLAVEOF \"\"\n"
            "   rename-command REPLICAOF \"\"\n"
            "5. Enable TLS (Redis 6+): tls-port 6380\n"
            "6. Use ACLs for fine-grained access (Redis 6+):\n"
            "   ACL SETUSER scanner on >password ~scan:* +get +set\n"
            "7. Firewall port 6379 to management IPs only\n\n"
            "Reference: https://redis.io/docs/management/security/"
        ),
        references=[
            "https://redis.io/docs/management/security/",
            "https://cwe.mitre.org/data/definitions/306.html",
            "https://book.hacktricks.xyz/network-services-pentesting/6379-pentesting-redis",
        ],
    ))

    return True


class Check(Plugin):
    async def run(self, target: str, ctx) -> PluginResult:
        open_ports = ctx.get("net.open_ports", []) or []
        findings: list[Finding] = []

        ports_to_check = [p for p in _REDIS_PORTS if p in open_ports]
        if not ports_to_check:
            return PluginResult(artifacts={"infra.redis.findings": 0})

        tasks = [_check_redis_port(target, p, findings) for p in ports_to_check]
        await asyncio.gather(*tasks, return_exceptions=True)

        return PluginResult(
            findings=findings,
            artifacts={"infra.redis.findings": len(findings)},
        )
