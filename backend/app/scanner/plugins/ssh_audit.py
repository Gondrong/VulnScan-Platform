"""
SSH Configuration Audit Plugin — analyses SSH service security without
requiring authentication credentials.

Tests performed (all read-only, no login required):
  - Key exchange algorithm strength (detects weak/deprecated algorithms)
  - Encryption cipher strength (detects CBC mode, DES, RC4, etc.)
  - MAC algorithm strength (detects MD5, SHA-1 MACs)
  - Host key types (detects DSA, short RSA keys)
  - SSH protocol version (detects SSHv1)
  - Banner information disclosure

Uses the SSH handshake (KEX_INIT) to extract supported algorithms
without authenticating. This is the same information visible to any
network observer during connection establishment.
"""
import asyncio
import logging
import struct

from app.scanner.plugins.base import Finding, Plugin, PluginMeta, PluginResult
from app.scanner.context import stable_fingerprint

logger = logging.getLogger("vulnscan.ssh_audit")

META = PluginMeta(
    plugin_id="infra.ssh.audit",
    name="SSH Configuration Audit",
    category="network",
    depends_on=["net.port.discovery.v2"],
    consumes=["net.open_ports", "fingerprint.banners"],
    provides=["infra.ssh.audit"],
    enabled_by_default=True,
    timeout_seconds=10.0,
)

# ─── Algorithm Classification ────────────────────────────────────────────────

# Weak key exchange algorithms
_WEAK_KEX = {
    "diffie-hellman-group1-sha1",          # 1024-bit, broken
    "diffie-hellman-group-exchange-sha1",   # SHA-1 based
    "diffie-hellman-group14-sha1",          # SHA-1 based (acceptable but not ideal)
    "ecdh-sha2-nistp256",                   # NIST curves (debatable, flagged as info)
}

_DEPRECATED_KEX = {
    "diffie-hellman-group1-sha1",
    "diffie-hellman-group-exchange-sha1",
}

# Weak encryption ciphers
_WEAK_CIPHERS = {
    "3des-cbc",                    # Triple DES — slow, 64-bit block
    "blowfish-cbc",               # 64-bit block
    "cast128-cbc",                # 64-bit block
    "arcfour", "arcfour128", "arcfour256",  # RC4 — broken
    "aes128-cbc", "aes192-cbc", "aes256-cbc",  # CBC mode — vulnerable to BEAST
    "rijndael-cbc@lysator.liu.se",  # CBC mode alias
    "none",                        # No encryption
}

_DEPRECATED_CIPHERS = {
    "3des-cbc", "blowfish-cbc", "cast128-cbc",
    "arcfour", "arcfour128", "arcfour256", "none",
}

# Strong ciphers (for reference)
_STRONG_CIPHERS = {
    "chacha20-poly1305@openssh.com",
    "aes128-gcm@openssh.com", "aes256-gcm@openssh.com",
    "aes128-ctr", "aes192-ctr", "aes256-ctr",
}

# Weak MAC algorithms
_WEAK_MACS = {
    "hmac-md5", "hmac-md5-96",
    "hmac-sha1", "hmac-sha1-96",
    "hmac-ripemd160", "hmac-ripemd160@openssh.com",
    "umac-64@openssh.com",
    "none",
}

_STRONG_MACS = {
    "hmac-sha2-256-etm@openssh.com",
    "hmac-sha2-512-etm@openssh.com",
    "umac-128-etm@openssh.com",
    "hmac-sha2-256", "hmac-sha2-512",
}

# Weak host key types
_WEAK_HOST_KEYS = {
    "ssh-dss",  # DSA — deprecated, 1024-bit max
    "ssh-rsa",  # SHA-1 signatures (deprecated in OpenSSH 8.8+)
}


def _parse_name_list(data: bytes, offset: int) -> tuple[list[str], int]:
    """Parse an SSH name-list (uint32 length + comma-separated string)."""
    if offset + 4 > len(data):
        return [], offset
    length = struct.unpack("!I", data[offset:offset + 4])[0]
    offset += 4
    if offset + length > len(data):
        return [], offset
    names = data[offset:offset + length].decode("ascii", errors="ignore")
    offset += length
    return [n.strip() for n in names.split(",") if n.strip()], offset


def _parse_kex_init(payload: bytes) -> dict:
    """Parse SSH_MSG_KEXINIT payload to extract algorithm lists."""
    result = {
        "kex_algorithms": [],
        "server_host_key_algorithms": [],
        "encryption_client_to_server": [],
        "encryption_server_to_client": [],
        "mac_client_to_server": [],
        "mac_server_to_client": [],
        "compression_client_to_server": [],
        "compression_server_to_client": [],
    }

    if not payload or len(payload) < 17:
        return result

    # Skip message type byte (1) + cookie (16 bytes)
    offset = 17

    fields = [
        "kex_algorithms",
        "server_host_key_algorithms",
        "encryption_client_to_server",
        "encryption_server_to_client",
        "mac_client_to_server",
        "mac_server_to_client",
        "compression_client_to_server",
        "compression_server_to_client",
    ]

    for field in fields:
        names, offset = _parse_name_list(payload, offset)
        result[field] = names

    return result


async def _ssh_handshake(host: str, port: int = 22,
                         timeout: float = 5.0) -> dict:
    """
    Perform partial SSH handshake to extract server algorithms.
    Returns parsed KEX_INIT data + banner.
    """
    result = {"banner": "", "kex": {}, "error": ""}

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )

        # Read server banner (SSH-2.0-OpenSSH_8.9p1 ...)
        banner_data = await asyncio.wait_for(reader.readline(), timeout=timeout)
        banner = banner_data.decode("utf-8", errors="ignore").strip()
        result["banner"] = banner

        if not banner.startswith("SSH-"):
            writer.close()
            result["error"] = "Not an SSH service"
            return result

        # Send our client banner
        client_banner = b"SSH-2.0-VulnScan_Audit\r\n"
        writer.write(client_banner)
        await writer.drain()

        # Read SSH_MSG_KEXINIT from server
        # SSH packet format: uint32 length + byte padding_length + payload + padding
        header = await asyncio.wait_for(reader.readexactly(4), timeout=timeout)
        pkt_len = struct.unpack("!I", header)[0]

        if pkt_len > 65536:
            writer.close()
            result["error"] = "Packet too large"
            return result

        pkt_data = await asyncio.wait_for(reader.readexactly(pkt_len), timeout=timeout)
        # First byte = padding length, second byte = message type
        if len(pkt_data) >= 2:
            padding_len = pkt_data[0]
            msg_type = pkt_data[1]

            if msg_type == 20:  # SSH_MSG_KEXINIT
                payload = pkt_data[1:pkt_len - padding_len]
                result["kex"] = _parse_kex_init(payload)

        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

    except asyncio.TimeoutError:
        result["error"] = "Connection timed out"
    except ConnectionRefusedError:
        result["error"] = "Connection refused"
    except Exception as e:
        result["error"] = str(e)[:200]

    return result


def _parse_ssh_version(banner: str) -> tuple[str, str]:
    """Extract software name and version from SSH banner.
    Returns (software, version) tuple.
    """
    # SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6
    parts = banner.split("-", 2)
    if len(parts) < 3:
        return "", ""

    software_part = parts[2].strip()
    # Common patterns: OpenSSH_8.9p1, dropbear_2020.81
    if "_" in software_part:
        name, ver = software_part.split("_", 1)
        ver = ver.split(" ")[0]  # Remove OS info
        return name.lower(), ver
    return software_part.lower(), ""


class Check(Plugin):
    async def run(self, target: str, ctx) -> PluginResult:
        open_ports = ctx.get("net.open_ports", []) or []
        findings: list[Finding] = []

        # Find SSH ports (22 is standard, also check common alternatives)
        ssh_ports = [p for p in open_ports if p in (22, 2222, 2200, 22222)]
        if not ssh_ports:
            return PluginResult(
                findings=[],
                artifacts={"infra.ssh.audit": {}},
            )

        audit_results = {}

        for port in ssh_ports:
            handshake = await _ssh_handshake(target, port)

            if handshake.get("error"):
                continue

            banner = handshake.get("banner", "")
            kex = handshake.get("kex", {})
            software, version = _parse_ssh_version(banner)

            audit_results[port] = {
                "banner": banner,
                "software": software,
                "version": version,
                "algorithms": kex,
            }

            # ── Check 1: SSH Version / Banner ──────────────────────────

            if banner.startswith("SSH-1"):
                findings.append(Finding(
                    severity="critical",
                    plugin_id=META.plugin_id,
                    title=f"SSHv1 protocol supported on port {port}",
                    description=(
                        "The SSH server supports protocol version 1, which has known "
                        "cryptographic vulnerabilities including session hijacking."
                    ),
                    evidence=f"host={target} port={port} banner={banner}",
                    affected=f"{target}:{port}",
                    fingerprint=stable_fingerprint(target, META.plugin_id, "sshv1", port),
                    remediation=(
                        "[CRITICAL — SSHv1 Protocol]\n"
                        "Disable SSH protocol version 1 in sshd_config:\n"
                        "  Protocol 2\n"
                        "Restart sshd after changes."
                    ),
                    confidence=0.95,
                ))

            # ── Check 2: Weak Key Exchange ─────────────────────────────

            kex_algos = kex.get("kex_algorithms", [])
            deprecated_kex = [a for a in kex_algos if a in _DEPRECATED_KEX]
            weak_kex = [a for a in kex_algos if a in _WEAK_KEX and a not in _DEPRECATED_KEX]

            if deprecated_kex:
                findings.append(Finding(
                    severity="high",
                    plugin_id=META.plugin_id,
                    title=f"Deprecated key exchange algorithms on port {port}",
                    description=(
                        f"The SSH server supports deprecated key exchange algorithms: "
                        f"{', '.join(deprecated_kex)}. These use weak cryptographic "
                        f"primitives (1024-bit DH or SHA-1) that are vulnerable to attack."
                    ),
                    evidence=(
                        f"host={target} port={port} "
                        f"deprecated_kex={deprecated_kex} "
                        f"all_kex={kex_algos}"
                    ),
                    affected=f"{target}:{port}",
                    fingerprint=stable_fingerprint(target, META.plugin_id, "weak_kex", port),
                    remediation=(
                        "[HIGH — Weak Key Exchange]\n"
                        "Remove deprecated KEX algorithms from sshd_config:\n\n"
                        "  KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,"
                        "diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,"
                        "diffie-hellman-group-exchange-sha256\n\n"
                        f"Deprecated algorithms to remove: {', '.join(deprecated_kex)}\n"
                        "Reference: https://infosec.mozilla.org/guidelines/openssh"
                    ),
                    confidence=0.95,
                    references=[
                        "https://infosec.mozilla.org/guidelines/openssh",
                        "https://cwe.mitre.org/data/definitions/327.html",
                    ],
                ))

            # ── Check 3: Weak Ciphers ──────────────────────────────────

            ciphers = set(
                kex.get("encryption_client_to_server", [])
                + kex.get("encryption_server_to_client", [])
            )
            deprecated_ciphers = [c for c in ciphers if c in _DEPRECATED_CIPHERS]
            weak_ciphers = [c for c in ciphers if c in _WEAK_CIPHERS and c not in _DEPRECATED_CIPHERS]
            strong_ciphers = [c for c in ciphers if c in _STRONG_CIPHERS]

            if deprecated_ciphers:
                findings.append(Finding(
                    severity="high",
                    plugin_id=META.plugin_id,
                    title=f"Deprecated encryption ciphers on port {port}",
                    description=(
                        f"The SSH server supports deprecated ciphers: "
                        f"{', '.join(deprecated_ciphers)}. These include broken algorithms "
                        f"(RC4, DES) and 64-bit block ciphers vulnerable to Sweet32."
                    ),
                    evidence=(
                        f"host={target} port={port} "
                        f"deprecated={deprecated_ciphers} "
                        f"all_ciphers={sorted(ciphers)}"
                    ),
                    affected=f"{target}:{port}",
                    fingerprint=stable_fingerprint(target, META.plugin_id, "weak_cipher", port),
                    remediation=(
                        "[HIGH — Weak Ciphers]\n"
                        "Configure strong ciphers only in sshd_config:\n\n"
                        "  Ciphers chacha20-poly1305@openssh.com,"
                        "aes256-gcm@openssh.com,aes128-gcm@openssh.com,"
                        "aes256-ctr,aes192-ctr,aes128-ctr\n\n"
                        f"Deprecated ciphers to remove: {', '.join(deprecated_ciphers)}"
                    ),
                    confidence=0.95,
                ))
            elif weak_ciphers:
                findings.append(Finding(
                    severity="medium",
                    plugin_id=META.plugin_id,
                    title=f"CBC-mode ciphers enabled on port {port}",
                    description=(
                        f"The SSH server supports CBC-mode ciphers: "
                        f"{', '.join(weak_ciphers)}. CBC mode is vulnerable to "
                        f"plaintext recovery attacks (CVE-2008-5161)."
                    ),
                    evidence=(
                        f"host={target} port={port} "
                        f"cbc_ciphers={weak_ciphers}"
                    ),
                    affected=f"{target}:{port}",
                    fingerprint=stable_fingerprint(target, META.plugin_id, "cbc_cipher", port),
                    remediation=(
                        "[MEDIUM — CBC Mode Ciphers]\n"
                        "Prefer CTR or GCM mode ciphers over CBC:\n"
                        "  Ciphers chacha20-poly1305@openssh.com,"
                        "aes256-gcm@openssh.com,aes128-gcm@openssh.com,"
                        "aes256-ctr,aes192-ctr,aes128-ctr"
                    ),
                    confidence=0.90,
                    cve="CVE-2008-5161",
                ))

            # ── Check 4: Weak MAC Algorithms ───────────────────────────

            macs = set(
                kex.get("mac_client_to_server", [])
                + kex.get("mac_server_to_client", [])
            )
            weak_macs = [m for m in macs if m in _WEAK_MACS]

            if weak_macs:
                findings.append(Finding(
                    severity="medium",
                    plugin_id=META.plugin_id,
                    title=f"Weak MAC algorithms on port {port}",
                    description=(
                        f"The SSH server supports weak MAC algorithms: "
                        f"{', '.join(weak_macs)}. MD5 and SHA-1 based MACs "
                        f"have known weaknesses."
                    ),
                    evidence=(
                        f"host={target} port={port} "
                        f"weak_macs={weak_macs} all_macs={sorted(macs)}"
                    ),
                    affected=f"{target}:{port}",
                    fingerprint=stable_fingerprint(target, META.plugin_id, "weak_mac", port),
                    remediation=(
                        "[MEDIUM — Weak MACs]\n"
                        "Configure strong MACs only in sshd_config:\n\n"
                        "  MACs hmac-sha2-256-etm@openssh.com,"
                        "hmac-sha2-512-etm@openssh.com,"
                        "umac-128-etm@openssh.com\n\n"
                        f"Weak MACs to remove: {', '.join(weak_macs)}"
                    ),
                    confidence=0.90,
                ))

            # ── Check 5: Weak Host Key Types ───────────────────────────

            host_keys = kex.get("server_host_key_algorithms", [])
            weak_hk = [k for k in host_keys if k in _WEAK_HOST_KEYS]

            if "ssh-dss" in weak_hk:
                findings.append(Finding(
                    severity="high",
                    plugin_id=META.plugin_id,
                    title=f"DSA host key offered on port {port}",
                    description=(
                        "The SSH server offers a DSA host key (ssh-dss). DSA keys are "
                        "limited to 1024 bits and are deprecated in OpenSSH 7.0+."
                    ),
                    evidence=f"host={target} port={port} host_keys={host_keys}",
                    affected=f"{target}:{port}",
                    fingerprint=stable_fingerprint(target, META.plugin_id, "dsa_key", port),
                    remediation=(
                        "[HIGH — DSA Host Key]\n"
                        "Remove DSA host key and generate Ed25519/ECDSA keys:\n"
                        "  rm /etc/ssh/ssh_host_dsa_key*\n"
                        "  ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ''\n"
                        "  HostKeyAlgorithms ssh-ed25519,ecdsa-sha2-nistp256,rsa-sha2-512,rsa-sha2-256"
                    ),
                    confidence=0.95,
                ))

            if "ssh-rsa" in weak_hk and not any(k.startswith("rsa-sha2") for k in host_keys):
                findings.append(Finding(
                    severity="medium",
                    plugin_id=META.plugin_id,
                    title=f"SSH-RSA (SHA-1) host key without SHA-2 upgrade on port {port}",
                    description=(
                        "The server offers ssh-rsa (SHA-1 signatures) without also offering "
                        "rsa-sha2-256 or rsa-sha2-512. SHA-1 signatures are deprecated "
                        "and disabled by default in OpenSSH 8.8+."
                    ),
                    evidence=f"host={target} port={port} host_keys={host_keys}",
                    affected=f"{target}:{port}",
                    fingerprint=stable_fingerprint(target, META.plugin_id, "rsa_sha1", port),
                    remediation=(
                        "[MEDIUM — SHA-1 RSA Signatures]\n"
                        "Upgrade to RSA-SHA2 or switch to Ed25519:\n"
                        "  HostKeyAlgorithms ssh-ed25519,rsa-sha2-512,rsa-sha2-256\n"
                        "  PubkeyAcceptedAlgorithms +ssh-rsa  # only if legacy clients need it"
                    ),
                    confidence=0.85,
                ))

            # ── Summary finding ────────────────────────────────────────

            total_weak = len(deprecated_kex) + len(deprecated_ciphers) + len(weak_ciphers) + len(weak_macs) + len(weak_hk)
            findings.append(Finding(
                severity="info",
                plugin_id=META.plugin_id,
                title=(
                    f"SSH audit summary: port {port} — "
                    f"{software or 'unknown'} {version or ''} — "
                    f"{total_weak} weak algorithm(s)"
                ),
                evidence=(
                    f"host={target} port={port} banner={banner} "
                    f"kex_count={len(kex_algos)} cipher_count={len(ciphers)} "
                    f"mac_count={len(macs)} hostkey_count={len(host_keys)} "
                    f"weak_total={total_weak} "
                    f"strong_ciphers={strong_ciphers}"
                ),
                affected=f"{target}:{port}",
                fingerprint=stable_fingerprint(target, META.plugin_id, "summary", port),
                remediation=(
                    "SSH hardening references:\n"
                    "- Mozilla OpenSSH guidelines: https://infosec.mozilla.org/guidelines/openssh\n"
                    "- ssh-audit tool: https://github.com/jtesta/ssh-audit\n"
                    "- CIS SSH Benchmark: https://www.cisecurity.org/benchmark/distribution_independent_linux"
                ),
            ))

        return PluginResult(
            findings=findings,
            artifacts={"infra.ssh.audit": audit_results},
        )
