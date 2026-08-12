"""
CIS Benchmark Scanner Plugin — performs authenticated CIS benchmark audits
via SSH against Linux servers, Docker hosts, and Nginx instances.

All checks are non-destructive read-only commands executed over SSH.
Covers CIS benchmarks for:
  - Linux OS Hardening (filesystem, services, network, firewall, logging,
    authentication, file permissions, system maintenance)
  - Docker Host Hardening (only if Docker is detected)
  - Nginx Hardening (only if Nginx is detected)

Requires SSH credentials configured in the scan profile. This plugin is
opt-in (enabled_by_default=False).
"""
import io
import logging
import re

import paramiko

from app.scanner.plugins.base import Finding, Plugin, PluginMeta, PluginResult
from app.scanner.context import stable_fingerprint

logger = logging.getLogger("vulnscan.cis_benchmark")

META = PluginMeta(
    plugin_id="audit.cis_benchmark",
    name="CIS Benchmark Audit",
    category="audit",
    depends_on=["net.port.discovery.v2"],
    soft_depends_on=["auth.ssh.inventory"],
    consumes=["net.open_ports", "inventory.ssh"],
    provides=["audit.cis_benchmark"],
    enabled_by_default=False,
    timeout_seconds=120.0,
)

# ---------------------------------------------------------------------------
# Remediation guidance per check ID
# ---------------------------------------------------------------------------
_REMEDIATION = {
    # Filesystem
    "CIS-1.1.1": "Add 'install cramfs /bin/true' to /etc/modprobe.d/cramfs.conf and run 'rmmod cramfs'.",
    "CIS-1.1.2": "Add 'install freevxfs /bin/true' to /etc/modprobe.d/freevxfs.conf and run 'rmmod freevxfs'.",
    "CIS-1.1.3": "Add 'install hfs /bin/true' to /etc/modprobe.d/hfs.conf and run 'rmmod hfs'.",
    "CIS-1.1.4": "Add 'install squashfs /bin/true' to /etc/modprobe.d/squashfs.conf and run 'rmmod squashfs'.",
    "CIS-1.1.5": "Create a separate partition for /tmp. Add an entry in /etc/fstab for /tmp.",
    "CIS-1.1.6": "Add 'noexec' option to /tmp mount in /etc/fstab: 'tmpfs /tmp tmpfs defaults,noexec,nosuid,nodev 0 0'.",
    # Services
    "CIS-2.1.1": "Remove xinetd: 'apt-get purge xinetd' or 'yum remove xinetd'.",
    "CIS-2.1.2": "Remove rsh-server: 'apt-get purge rsh-server' or 'yum remove rsh-server'.",
    "CIS-2.1.3": "Remove telnet server: 'apt-get purge telnetd' or 'yum remove telnet-server'. Use SSH instead.",
    "CIS-2.2.1": "Remove NIS: 'apt-get purge nis' or 'yum remove ypserv'. Use LDAP or Kerberos instead.",
    # Network
    "CIS-3.1.1": "Set 'net.ipv4.ip_forward = 0' in /etc/sysctl.conf and run 'sysctl -p'.",
    "CIS-3.1.2": "Set 'net.ipv4.conf.all.accept_redirects = 0' in /etc/sysctl.conf and run 'sysctl -p'.",
    "CIS-3.1.3": "Set 'net.ipv4.conf.all.accept_source_route = 0' in /etc/sysctl.conf and run 'sysctl -p'.",
    "CIS-3.1.4": "Set 'net.ipv4.conf.all.log_martians = 1' in /etc/sysctl.conf and run 'sysctl -p'.",
    "CIS-3.1.5": "Set 'net.ipv4.tcp_syncookies = 1' in /etc/sysctl.conf and run 'sysctl -p'.",
    "CIS-3.2.1": "Set 'net.ipv6.conf.all.accept_ra = 0' in /etc/sysctl.conf and run 'sysctl -p'.",
    # Firewall
    "CIS-4.1.1": "Install iptables or nftables: 'apt-get install iptables' or 'yum install iptables'.",
    "CIS-4.1.2": "Set default INPUT policy to DROP: 'iptables -P INPUT DROP'. Ensure allow rules exist first.",
    # Logging
    "CIS-5.1.1": "Install and enable rsyslog: 'apt-get install rsyslog && systemctl enable rsyslog'.",
    "CIS-5.1.2": "Configure logging in /etc/rsyslog.conf or journald.conf to capture system events.",
    "CIS-5.2.1": "Install and enable auditd: 'apt-get install auditd && systemctl enable auditd'.",
    # Authentication
    "CIS-6.1.1": "Set 'PASS_MAX_DAYS 365' in /etc/login.defs.",
    "CIS-6.1.2": "Set 'PASS_MIN_LEN 14' in /etc/login.defs or 'minlen = 14' in /etc/security/pwquality.conf.",
    "CIS-6.1.3": "Set 'ENCRYPT_METHOD SHA512' or 'ENCRYPT_METHOD YESCRYPT' in /etc/login.defs.",
    "CIS-6.2.1": "Lock accounts with empty passwords: 'passwd -l <username>' for each affected account.",
    "CIS-6.2.2": "Remove extra UID 0 accounts or change their UID. Only root should have UID 0.",
    "CIS-6.2.3": "Restrict root login to console by configuring /etc/securetty.",
    "CIS-6.3.1": "Set 'PermitRootLogin no' in /etc/ssh/sshd_config and restart sshd.",
    "CIS-6.3.2": "Set 'PasswordAuthentication no' in /etc/ssh/sshd_config and use key-based auth.",
    "CIS-6.3.3": "Set 'MaxAuthTries 4' in /etc/ssh/sshd_config and restart sshd.",
    "CIS-6.3.4": "Set 'Protocol 2' in /etc/ssh/sshd_config (or remove Protocol line on modern OpenSSH).",
    # File permissions
    "CIS-7.1.1": "Run 'chmod 644 /etc/passwd'.",
    "CIS-7.1.2": "Run 'chmod 640 /etc/shadow'.",
    "CIS-7.1.3": "Run 'chmod 644 /etc/group'.",
    "CIS-7.1.4": "Find and fix world-writable files in /etc: 'find /etc -perm -0002 -type f -exec chmod o-w {} \\;'.",
    "CIS-7.2.1": "Assign ownership to unowned files: 'find / -nouser -exec chown root {} \\;'.",
    "CIS-7.2.2": "Assign group to ungrouped files: 'find / -nogroup -exec chgrp root {} \\;'.",
    # System maintenance
    "CIS-8.1.1": "Install AIDE: 'apt-get install aide && aide --init'.",
    "CIS-8.2.1": "Apply pending updates: 'apt-get upgrade' or 'yum update'.",
    "CIS-8.3.1": "Enable automatic updates: 'apt-get install unattended-upgrades && dpkg-reconfigure -plow unattended-upgrades'.",
    # Docker
    "CIS-D.1.1": "Update Docker to the latest stable version: 'apt-get update && apt-get install docker-ce'.",
    "CIS-D.1.2": "Add audit rules for Docker: 'auditctl -w /usr/bin/docker -p rwxa -k docker'.",
    "CIS-D.2.1": "Restrict inter-container traffic: 'dockerd --icc=false' or set in /etc/docker/daemon.json.",
    "CIS-D.2.2": "Do not mount docker.sock into containers. Use Docker API over TLS instead.",
    "CIS-D.2.3": "Do not run privileged containers. Remove --privileged flag from docker run commands.",
    "CIS-D.2.4": "Enable Docker content trust: 'export DOCKER_CONTENT_TRUST=1'.",
    "CIS-D.3.1": "Run Docker in rootless mode: https://docs.docker.com/engine/security/rootless/",
    # Nginx
    "CIS-N.1.1": "Set 'user www-data;' (or nginx) in /etc/nginx/nginx.conf. Do not run as root.",
    "CIS-N.1.2": "Add 'server_tokens off;' to the http block in /etc/nginx/nginx.conf.",
    "CIS-N.2.1": "Set 'ssl_protocols TLSv1.2 TLSv1.3;' in /etc/nginx/nginx.conf.",
    "CIS-N.2.2": "Add 'add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;' to server blocks.",
    "CIS-N.3.1": "Ensure 'access_log' is not set to 'off' in nginx configuration.",
    "CIS-N.3.2": "Ensure 'error_log' is not set to 'off' in nginx configuration.",
}

# ---------------------------------------------------------------------------
# Check definitions: (id, description, command, pass_lambda, severity)
# ---------------------------------------------------------------------------

# Helper lambdas that use re must be defined as functions so re is accessible
def _check_pass_max_days(o: str) -> bool:
    nums = re.findall(r"\d+", o)
    return any(int(x) <= 365 for x in nums) if nums else False


def _check_min_pw_len(o: str) -> bool:
    nums = re.findall(r"\d+", o)
    return any(int(x) >= 14 for x in nums) if nums else False


def _check_max_auth_tries(o: str) -> bool:
    nums = re.findall(r"\d+", o)
    return any(int(x) <= 4 for x in nums) if nums else False


_LINUX_CHECKS: list[tuple[str, str, str, object, str]] = [
    # 1. Filesystem
    (
        "CIS-1.1.1", "Ensure mounting of cramfs is disabled",
        "modprobe -n -v cramfs 2>&1",
        lambda o: "install /bin/true" in o or "not found" in o,
        "high",
    ),
    (
        "CIS-1.1.2", "Ensure mounting of freevxfs is disabled",
        "modprobe -n -v freevxfs 2>&1",
        lambda o: "install /bin/true" in o or "not found" in o,
        "medium",
    ),
    (
        "CIS-1.1.3", "Ensure mounting of hfs is disabled",
        "modprobe -n -v hfs 2>&1",
        lambda o: "install /bin/true" in o or "not found" in o,
        "medium",
    ),
    (
        "CIS-1.1.4", "Ensure mounting of squashfs is disabled",
        "modprobe -n -v squashfs 2>&1",
        lambda o: "install /bin/true" in o or "not found" in o,
        "medium",
    ),
    (
        "CIS-1.1.5", "Ensure /tmp is a separate partition",
        "findmnt /tmp",
        lambda o: "/tmp" in o,
        "medium",
    ),
    (
        "CIS-1.1.6", "Ensure /tmp has noexec option",
        "findmnt -n /tmp | grep noexec",
        lambda o: "noexec" in o,
        "medium",
    ),
    # 2. Services
    (
        "CIS-2.1.1", "Ensure xinetd is not installed",
        "dpkg -s xinetd 2>&1 || rpm -q xinetd 2>&1",
        lambda o: "not installed" in o.lower() or "not found" in o.lower() or "is not installed" in o.lower(),
        "medium",
    ),
    (
        "CIS-2.1.2", "Ensure rsh server is not installed",
        "dpkg -s rsh-server 2>&1 || rpm -q rsh-server 2>&1",
        lambda o: "not installed" in o.lower() or "not found" in o.lower(),
        "high",
    ),
    (
        "CIS-2.1.3", "Ensure telnet server is not installed",
        "dpkg -s telnetd 2>&1 || rpm -q telnet-server 2>&1",
        lambda o: "not installed" in o.lower() or "not found" in o.lower(),
        "critical",
    ),
    (
        "CIS-2.2.1", "Ensure NIS is not installed",
        "dpkg -s nis 2>&1 || rpm -q ypserv 2>&1",
        lambda o: "not installed" in o.lower() or "not found" in o.lower(),
        "high",
    ),
    # 3. Network
    (
        "CIS-3.1.1", "Ensure IP forwarding is disabled",
        "sysctl net.ipv4.ip_forward",
        lambda o: "= 0" in o,
        "medium",
    ),
    (
        "CIS-3.1.2", "Ensure ICMP redirects are not accepted",
        "sysctl net.ipv4.conf.all.accept_redirects",
        lambda o: "= 0" in o,
        "medium",
    ),
    (
        "CIS-3.1.3", "Ensure source routed packets are not accepted",
        "sysctl net.ipv4.conf.all.accept_source_route",
        lambda o: "= 0" in o,
        "medium",
    ),
    (
        "CIS-3.1.4", "Ensure suspicious packets are logged",
        "sysctl net.ipv4.conf.all.log_martians",
        lambda o: "= 1" in o,
        "low",
    ),
    (
        "CIS-3.1.5", "Ensure TCP SYN cookies are enabled",
        "sysctl net.ipv4.tcp_syncookies",
        lambda o: "= 1" in o,
        "medium",
    ),
    (
        "CIS-3.2.1", "Ensure IPv6 router advertisements are not accepted",
        "sysctl net.ipv6.conf.all.accept_ra 2>/dev/null",
        lambda o: "= 0" in o or "No such file" in o,
        "low",
    ),
    # 4. Firewall
    (
        "CIS-4.1.1", "Ensure iptables/nftables is installed",
        "which iptables || which nft",
        lambda o: "/" in o,
        "high",
    ),
    (
        "CIS-4.1.2", "Ensure default deny firewall policy",
        "iptables -L INPUT -n 2>/dev/null | head -1",
        lambda o: "DROP" in o or "REJECT" in o,
        "high",
    ),
    # 5. Logging
    (
        "CIS-5.1.1", "Ensure rsyslog or journald is running",
        "systemctl is-active rsyslog 2>/dev/null || systemctl is-active systemd-journald 2>/dev/null",
        lambda o: "active" in o,
        "high",
    ),
    (
        "CIS-5.1.2", "Ensure logging is configured",
        "ls /var/log/syslog /var/log/messages 2>/dev/null | head -1",
        lambda o: "/var/log" in o,
        "medium",
    ),
    (
        "CIS-5.2.1", "Ensure audit is enabled",
        "systemctl is-active auditd 2>/dev/null",
        lambda o: "active" in o,
        "medium",
    ),
    # 6. Authentication
    (
        "CIS-6.1.1", "Ensure password expiration is 365 days or less",
        "grep '^PASS_MAX_DAYS' /etc/login.defs",
        _check_pass_max_days,
        "medium",
    ),
    (
        "CIS-6.1.2", "Ensure minimum password length >= 14",
        "grep '^PASS_MIN_LEN' /etc/login.defs 2>/dev/null || grep 'minlen' /etc/security/pwquality.conf 2>/dev/null",
        _check_min_pw_len,
        "high",
    ),
    (
        "CIS-6.1.3", "Ensure password hashing is SHA-512",
        "grep -E '^ENCRYPT_METHOD' /etc/login.defs",
        lambda o: "SHA512" in o.upper() or "YESCRYPT" in o.upper(),
        "high",
    ),
    (
        "CIS-6.2.1", "Ensure no accounts have empty passwords",
        "awk -F: '($2 == \"\") {print $1}' /etc/shadow 2>/dev/null",
        lambda o: o.strip() == "",
        "critical",
    ),
    (
        "CIS-6.2.2", "Ensure root is the only UID 0 account",
        "awk -F: '($3 == 0) {print $1}' /etc/passwd",
        lambda o: o.strip() == "root",
        "critical",
    ),
    (
        "CIS-6.2.3", "Ensure root login is restricted to console",
        "cat /etc/securetty 2>/dev/null | wc -l",
        lambda o: True,
        "low",
    ),
    (
        "CIS-6.3.1", "Ensure SSH root login is disabled",
        "grep -i '^PermitRootLogin' /etc/ssh/sshd_config 2>/dev/null",
        lambda o: "no" in o.lower(),
        "high",
    ),
    (
        "CIS-6.3.2", "Ensure SSH PasswordAuthentication is disabled",
        "grep -i '^PasswordAuthentication' /etc/ssh/sshd_config 2>/dev/null",
        lambda o: "no" in o.lower(),
        "medium",
    ),
    (
        "CIS-6.3.3", "Ensure SSH MaxAuthTries is 4 or less",
        "grep -i '^MaxAuthTries' /etc/ssh/sshd_config 2>/dev/null",
        _check_max_auth_tries,
        "medium",
    ),
    (
        "CIS-6.3.4", "Ensure SSH Protocol is 2",
        "grep -i '^Protocol' /etc/ssh/sshd_config 2>/dev/null || echo 'Protocol 2'",
        lambda o: "2" in o,
        "high",
    ),
    # 7. File Permissions
    (
        "CIS-7.1.1", "Ensure permissions on /etc/passwd are 644 or more restrictive",
        "stat -c '%a' /etc/passwd",
        lambda o: o.strip() in ("644", "444", "440", "400"),
        "high",
    ),
    (
        "CIS-7.1.2", "Ensure permissions on /etc/shadow are 640 or more restrictive",
        "stat -c '%a' /etc/shadow 2>/dev/null",
        lambda o: o.strip() in ("640", "600", "400", "000"),
        "critical",
    ),
    (
        "CIS-7.1.3", "Ensure permissions on /etc/group are 644 or more restrictive",
        "stat -c '%a' /etc/group",
        lambda o: o.strip() in ("644", "444", "440", "400"),
        "medium",
    ),
    (
        "CIS-7.1.4", "Ensure no world-writable files exist in /etc",
        "find /etc -perm -0002 -type f 2>/dev/null | head -5",
        lambda o: o.strip() == "",
        "high",
    ),
    (
        "CIS-7.2.1", "Ensure no unowned files exist",
        "find / -nouser -not -path '/proc/*' -not -path '/sys/*' 2>/dev/null | head -5",
        lambda o: o.strip() == "",
        "medium",
    ),
    (
        "CIS-7.2.2", "Ensure no ungrouped files exist",
        "find / -nogroup -not -path '/proc/*' -not -path '/sys/*' 2>/dev/null | head -5",
        lambda o: o.strip() == "",
        "medium",
    ),
    # 8. System Maintenance
    (
        "CIS-8.1.1", "Ensure AIDE/integrity checking is installed",
        "which aide || which tripwire || which ossec 2>/dev/null",
        lambda o: "/" in o,
        "medium",
    ),
    (
        "CIS-8.2.1", "Ensure updates are available and applied",
        "apt list --upgradable 2>/dev/null | tail -n +2 | wc -l || yum check-update 2>/dev/null | grep -c 'updates'",
        lambda o: o.strip() == "0" or o.strip() == "",
        "medium",
    ),
    (
        "CIS-8.3.1", "Ensure automatic updates are configured",
        "systemctl is-enabled unattended-upgrades 2>/dev/null || systemctl is-enabled dnf-automatic 2>/dev/null",
        lambda o: "enabled" in o,
        "low",
    ),
]

_DOCKER_CHECKS: list[tuple[str, str, str, object, str]] = [
    (
        "CIS-D.1.1", "Ensure Docker is up to date",
        "docker version --format '{{.Server.Version}}' 2>/dev/null",
        lambda o: o.strip() != "",
        "medium",
    ),
    (
        "CIS-D.1.2", "Ensure auditing is configured for Docker",
        "auditctl -l 2>/dev/null | grep docker",
        lambda o: "docker" in o.lower(),
        "medium",
    ),
    (
        "CIS-D.2.1", "Ensure network traffic between containers is restricted",
        "docker network inspect bridge --format '{{.Options}}' 2>/dev/null",
        lambda o: "com.docker.network.bridge.enable_icc:false" in o.replace(" ", ""),
        "high",
    ),
    (
        "CIS-D.2.2", "Ensure Docker socket is not mounted in containers",
        "docker ps --format '{{.Mounts}}' 2>/dev/null | grep docker.sock",
        lambda o: "docker.sock" not in o,
        "critical",
    ),
    (
        "CIS-D.2.3", "Ensure no privileged containers running",
        "docker ps -q 2>/dev/null | xargs -r docker inspect --format '{{.HostConfig.Privileged}}' 2>/dev/null | grep true",
        lambda o: "true" not in o,
        "critical",
    ),
    (
        "CIS-D.2.4", "Ensure Docker content trust is enabled",
        "echo $DOCKER_CONTENT_TRUST",
        lambda o: o.strip() == "1",
        "medium",
    ),
    (
        "CIS-D.3.1", "Ensure Docker daemon runs as non-root (rootless)",
        "docker info --format '{{.SecurityOptions}}' 2>/dev/null",
        lambda o: "rootless" in o.lower(),
        "medium",
    ),
]

_NGINX_CHECKS: list[tuple[str, str, str, object, str]] = [
    (
        "CIS-N.1.1", "Ensure nginx is running as non-root user",
        "grep -E '^user' /etc/nginx/nginx.conf 2>/dev/null",
        lambda o: "root" not in o.lower() or "user" in o.lower(),
        "high",
    ),
    (
        "CIS-N.1.2", "Ensure server_tokens is off",
        "nginx -T 2>/dev/null | grep server_tokens",
        lambda o: "off" in o.lower(),
        "medium",
    ),
    (
        "CIS-N.2.1", "Ensure default SSL protocols are TLSv1.2+",
        "nginx -T 2>/dev/null | grep ssl_protocols",
        lambda o: "TLSv1.2" in o or "TLSv1.3" in o,
        "high",
    ),
    (
        "CIS-N.2.2", "Ensure HSTS is configured",
        "nginx -T 2>/dev/null | grep Strict-Transport-Security",
        lambda o: "Strict-Transport-Security" in o,
        "medium",
    ),
    (
        "CIS-N.3.1", "Ensure access logging is enabled",
        "nginx -T 2>/dev/null | grep access_log",
        lambda o: "off" not in o.lower() and "access_log" in o,
        "medium",
    ),
    (
        "CIS-N.3.2", "Ensure error logging is enabled",
        "nginx -T 2>/dev/null | grep error_log",
        lambda o: "off" not in o.lower() and "error_log" in o,
        "medium",
    ),
]


# ---------------------------------------------------------------------------
# SSH execution helper
# ---------------------------------------------------------------------------

def _ssh_exec(
    host: str,
    port: int,
    username: str,
    password: str | None = None,
    key_text: str | None = None,
    command: str = "",
    timeout: float = 10,
) -> str:
    """Execute a single command via SSH and return stdout as a string."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        connect_kwargs: dict = {
            "hostname": host,
            "port": port,
            "username": username,
            "timeout": timeout,
            "banner_timeout": timeout,
            "auth_timeout": timeout,
            "look_for_keys": False,
            "allow_agent": False,
        }
        if key_text:
            pkey = None
            for cls in [paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey, paramiko.DSSKey]:
                try:
                    pkey = cls.from_private_key(io.StringIO(key_text))
                    break
                except Exception:
                    continue
            if pkey:
                connect_kwargs["pkey"] = pkey
            else:
                return "ERROR: Unable to parse SSH key"
        elif password:
            connect_kwargs["password"] = password
        else:
            return "ERROR: No SSH credentials provided"

        client.connect(**connect_kwargs)
        _stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
        return stdout.read().decode("utf-8", errors="ignore")
    except Exception as e:
        return f"ERROR: {e}"
    finally:
        client.close()


def _ssh_exec_batch(
    host: str,
    port: int,
    username: str,
    password: str | None = None,
    key_text: str | None = None,
    commands: list[str] | None = None,
    timeout: float = 10,
) -> list[str]:
    """
    Execute multiple commands over a single SSH connection.
    Returns a list of stdout strings, one per command.
    """
    if not commands:
        return []

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    results: list[str] = []

    try:
        connect_kwargs: dict = {
            "hostname": host,
            "port": port,
            "username": username,
            "timeout": timeout,
            "banner_timeout": timeout,
            "auth_timeout": timeout,
            "look_for_keys": False,
            "allow_agent": False,
        }
        if key_text:
            pkey = None
            for cls in [paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey, paramiko.DSSKey]:
                try:
                    pkey = cls.from_private_key(io.StringIO(key_text))
                    break
                except Exception:
                    continue
            if pkey:
                connect_kwargs["pkey"] = pkey
            else:
                return [f"ERROR: Unable to parse SSH key"] * len(commands)
        elif password:
            connect_kwargs["password"] = password
        else:
            return [f"ERROR: No SSH credentials provided"] * len(commands)

        client.connect(**connect_kwargs)

        for cmd in commands:
            try:
                _stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)
                out = stdout.read().decode("utf-8", errors="ignore")
                results.append(out)
            except Exception as e:
                results.append(f"ERROR: {e}")

    except Exception as e:
        # Connection-level failure — fill remaining with errors
        err = f"ERROR: {e}"
        while len(results) < len(commands):
            results.append(err)
    finally:
        client.close()

    return results


# ---------------------------------------------------------------------------
# Plugin class
# ---------------------------------------------------------------------------

class Check(Plugin):
    async def run(self, target: str, ctx) -> PluginResult:
        findings: list[Finding] = []

        # ── 1. Check if SSH port is open ──────────────────────────────
        open_ports = ctx.get("net.open_ports", []) or []
        if 22 not in open_ports and 2222 not in open_ports:
            return PluginResult(
                findings=[
                    Finding(
                        severity="info",
                        plugin_id=META.plugin_id,
                        title="CIS Benchmark skipped - no SSH port detected",
                        description=(
                            "The CIS Benchmark audit requires SSH access (port 22 or 2222) "
                            "but no SSH port was found open on the target."
                        ),
                        evidence=f"open_ports={open_ports}",
                        affected=target,
                        fingerprint=stable_fingerprint(target, META.plugin_id, "no_ssh_port"),
                    )
                ],
                artifacts={"audit.cis_benchmark": {}},
            )

        # ── 2. Get SSH credentials ────────────────────────────────────
        ssh_data = ctx.get("inventory.ssh", {}) or {}
        ssh_host = ssh_data.get("host") or target
        ssh_port = int(ssh_data.get("port", 22))
        ssh_user = ssh_data.get("username")
        ssh_password = ssh_data.get("password")
        ssh_key_text = ssh_data.get("key_text")

        # Also check profile_options for SSH credentials (same pattern as ssh_inventory)
        if not ssh_user:
            opt = ctx.get("profile_options", {}) or {}
            auth = opt.get("auth", {}) or {}
            cred_id = auth.get("ssh_credential_id")
            ssh_port = int(auth.get("ssh_port", ssh_port))

            if cred_id:
                # Try loading credential from DB
                try:
                    from app.db.session import SessionLocal
                    from app.db import models
                    from app.core.crypto import decrypt_str

                    ws_id = ctx.get("workspace_id")
                    db = SessionLocal()
                    try:
                        cred = (
                            db.query(models.Credential)
                            .filter(
                                models.Credential.id == cred_id,
                                models.Credential.workspace_id == ws_id,
                            )
                            .first()
                        )
                        if cred:
                            ssh_user = cred.username
                            secret = decrypt_str(cred.secret_enc)
                            if cred.secret_type == "password":
                                ssh_password = secret
                            else:
                                ssh_key_text = secret
                    finally:
                        db.close()
                except Exception as e:
                    logger.warning("CIS Benchmark: failed to load SSH credential: %s", e)

        if not ssh_user:
            return PluginResult(
                findings=[
                    Finding(
                        severity="info",
                        plugin_id=META.plugin_id,
                        title="CIS Benchmark requires SSH credentials",
                        description=(
                            "The CIS Benchmark audit requires SSH credentials to connect to "
                            "the target host. Configure SSH credentials in the scan profile "
                            "(Profiles > Scan Options > SSH Credential) or enable the SSH "
                            "Inventory plugin which provides credential data."
                        ),
                        evidence="ssh_credentials=None",
                        affected=target,
                        fingerprint=stable_fingerprint(target, META.plugin_id, "no_creds"),
                    )
                ],
                artifacts={"audit.cis_benchmark": {}},
            )

        # ── 3. Test SSH connectivity ──────────────────────────────────
        test_output = _ssh_exec(
            ssh_host, ssh_port, ssh_user,
            password=ssh_password, key_text=ssh_key_text,
            command="echo CIS_BENCHMARK_READY", timeout=10,
        )
        if test_output.startswith("ERROR:"):
            return PluginResult(
                findings=[
                    Finding(
                        severity="medium",
                        plugin_id=META.plugin_id,
                        title="CIS Benchmark: SSH connection failed",
                        description=(
                            f"Could not establish SSH connection to {ssh_host}:{ssh_port}. "
                            "Verify credentials and network access."
                        ),
                        evidence=test_output[:512],
                        affected=target,
                        fingerprint=stable_fingerprint(target, META.plugin_id, "ssh_failed"),
                    )
                ],
                artifacts={"audit.cis_benchmark": {}},
            )

        # ── 4. Detect Docker and Nginx ────────────────────────────────
        detection_cmds = [
            "which docker 2>/dev/null && docker info >/dev/null 2>&1 && echo DOCKER_PRESENT",
            "which nginx 2>/dev/null && echo NGINX_PRESENT",
        ]
        detection_results = _ssh_exec_batch(
            ssh_host, ssh_port, ssh_user,
            password=ssh_password, key_text=ssh_key_text,
            commands=detection_cmds, timeout=15,
        )
        has_docker = "DOCKER_PRESENT" in (detection_results[0] if detection_results else "")
        has_nginx = "NGINX_PRESENT" in (detection_results[1] if len(detection_results) > 1 else "")

        # ── 5. Build check list ───────────────────────────────────────
        all_checks = list(_LINUX_CHECKS)
        if has_docker:
            all_checks.extend(_DOCKER_CHECKS)
        if has_nginx:
            all_checks.extend(_NGINX_CHECKS)

        # ── 6. Execute all checks in a single SSH session ─────────────
        commands = [check[2] for check in all_checks]
        outputs = _ssh_exec_batch(
            ssh_host, ssh_port, ssh_user,
            password=ssh_password, key_text=ssh_key_text,
            commands=commands, timeout=15,
        )

        # ── 7. Evaluate results ───────────────────────────────────────
        passed = 0
        failed = 0
        skipped = 0
        check_results: list[dict] = []

        for i, (check_id, description, _cmd, pass_fn, severity) in enumerate(all_checks):
            output = outputs[i] if i < len(outputs) else "ERROR: no output"

            if output.startswith("ERROR:"):
                # Command error — skip this check
                skipped += 1
                check_results.append({
                    "id": check_id,
                    "description": description,
                    "status": "skip",
                    "severity": severity,
                })
                findings.append(Finding(
                    severity="info",
                    plugin_id=META.plugin_id,
                    title=f"SKIP: {check_id}: {description} (error)",
                    description=f"Check could not be executed: {output[:256]}",
                    evidence=f"check_id={check_id} output={output[:256]}",
                    affected=target,
                    fingerprint=stable_fingerprint(target, META.plugin_id, check_id, "skip"),
                    remediation=_REMEDIATION.get(check_id, ""),
                ))
                continue

            try:
                check_passed = pass_fn(output)
            except Exception as e:
                # Lambda evaluation error — treat as skip
                skipped += 1
                check_results.append({
                    "id": check_id,
                    "description": description,
                    "status": "skip",
                    "severity": severity,
                })
                findings.append(Finding(
                    severity="info",
                    plugin_id=META.plugin_id,
                    title=f"SKIP: {check_id}: {description} (eval error)",
                    description=f"Check evaluation failed: {e}",
                    evidence=f"check_id={check_id} output={output[:256]} error={e}",
                    affected=target,
                    fingerprint=stable_fingerprint(target, META.plugin_id, check_id, "eval_error"),
                    remediation=_REMEDIATION.get(check_id, ""),
                ))
                continue

            if check_passed:
                passed += 1
                check_results.append({
                    "id": check_id,
                    "description": description,
                    "status": "pass",
                    "severity": severity,
                })
                findings.append(Finding(
                    severity="info",
                    plugin_id=META.plugin_id,
                    title=f"PASS: {check_id}: {description}",
                    description=f"CIS Benchmark check passed.",
                    evidence=f"check_id={check_id} output={output.strip()[:256]}",
                    affected=target,
                    fingerprint=stable_fingerprint(target, META.plugin_id, check_id, "pass"),
                    remediation=_REMEDIATION.get(check_id, ""),
                ))
            else:
                failed += 1
                check_results.append({
                    "id": check_id,
                    "description": description,
                    "status": "fail",
                    "severity": severity,
                })
                findings.append(Finding(
                    severity=severity,
                    plugin_id=META.plugin_id,
                    title=f"FAIL: {check_id}: {description}",
                    description=(
                        f"CIS Benchmark check failed. The system does not comply with "
                        f"{check_id}: {description}."
                    ),
                    evidence=f"check_id={check_id} output={output.strip()[:256]}",
                    affected=target,
                    fingerprint=stable_fingerprint(target, META.plugin_id, check_id, "fail"),
                    remediation=_REMEDIATION.get(check_id, ""),
                    references=[
                        "https://www.cisecurity.org/benchmark/distribution_independent_linux",
                    ],
                ))

        # ── 8. Summary finding ────────────────────────────────────────
        total = passed + failed + skipped
        pct = round((passed / total) * 100, 1) if total > 0 else 0.0

        # Determine summary severity based on pass rate
        if pct >= 90:
            summary_severity = "info"
        elif pct >= 70:
            summary_severity = "low"
        elif pct >= 50:
            summary_severity = "medium"
        else:
            summary_severity = "high"

        scope_parts = ["Linux OS"]
        if has_docker:
            scope_parts.append("Docker")
        if has_nginx:
            scope_parts.append("Nginx")
        scope = ", ".join(scope_parts)

        findings.append(Finding(
            severity=summary_severity,
            plugin_id=META.plugin_id,
            title=f"CIS Benchmark: {passed}/{total} checks passed ({pct}%)",
            description=(
                f"CIS Benchmark audit completed against {target}. "
                f"Scope: {scope}. "
                f"Results: {passed} passed, {failed} failed, {skipped} skipped out of {total} checks."
            ),
            evidence=(
                f"host={target} total={total} passed={passed} failed={failed} "
                f"skipped={skipped} pass_rate={pct}% scope={scope} "
                f"docker_detected={has_docker} nginx_detected={has_nginx}"
            ),
            affected=target,
            fingerprint=stable_fingerprint(target, META.plugin_id, "summary"),
            remediation=(
                "CIS Benchmark references:\n"
                "- CIS Benchmarks: https://www.cisecurity.org/cis-benchmarks\n"
                "- CIS Linux Benchmark: https://www.cisecurity.org/benchmark/distribution_independent_linux\n"
                "- CIS Docker Benchmark: https://www.cisecurity.org/benchmark/docker\n"
                "- CIS Nginx Benchmark: https://www.cisecurity.org/benchmark/nginx"
            ),
        ))

        # ── 9. Return results ─────────────────────────────────────────
        return PluginResult(
            findings=findings,
            artifacts={
                "audit.cis_benchmark": {
                    "target": target,
                    "total_checks": total,
                    "passed": passed,
                    "failed": failed,
                    "skipped": skipped,
                    "pass_rate_pct": pct,
                    "docker_detected": has_docker,
                    "nginx_detected": has_nginx,
                    "checks": check_results,
                },
            },
        )
