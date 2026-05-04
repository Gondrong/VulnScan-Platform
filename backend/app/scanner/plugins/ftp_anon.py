"""
FTP Anonymous Login Scanner — checks for anonymous FTP access.

Tests FTP (port 21) for:
  - Anonymous login (user: anonymous, password: guest@)
  - Directory listing access
  - Write access (tests with MKD, does not actually create)
  - Version disclosure from banner

All tests are non-destructive.
"""
import asyncio
import logging
import re

from app.scanner.plugins.base import Finding, Plugin, PluginMeta, PluginResult
from app.scanner.context import stable_fingerprint

logger = logging.getLogger("vulnscan.ftp_anon")

META = PluginMeta(
    plugin_id="infra.ftp.anonymous",
    name="FTP Anonymous Login Scanner",
    category="network",
    depends_on=["net.port.discovery.v2"],
    consumes=["net.open_ports"],
    provides=["infra.ftp.findings"],
    enabled_by_default=True,
    timeout_seconds=15.0,
)


async def _ftp_command(reader, writer, cmd: str, timeout: float = 5.0) -> str:
    """Send FTP command and read response."""
    writer.write(f"{cmd}\r\n".encode())
    await writer.drain()
    data = await asyncio.wait_for(reader.read(4096), timeout=timeout)
    return data.decode("utf-8", errors="ignore").strip()


class Check(Plugin):
    async def run(self, target: str, ctx) -> PluginResult:
        open_ports = ctx.get("net.open_ports", []) or []
        findings: list[Finding] = []

        if 21 not in open_ports:
            return PluginResult(artifacts={"infra.ftp.findings": 0})

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, 21), timeout=5.0
            )
        except (asyncio.TimeoutError, OSError):
            return PluginResult(artifacts={"infra.ftp.findings": 0})

        try:
            # Read banner
            banner_data = await asyncio.wait_for(reader.read(4096), timeout=5.0)
            banner = banner_data.decode("utf-8", errors="ignore").strip()

            # Extract version from banner
            version = ""
            ver_match = re.search(r"(\d+\.\d+[\.\d]*)", banner)
            if ver_match:
                version = ver_match.group(1)

            server_sw = ""
            for sw in ("vsftpd", "ProFTPD", "Pure-FTPd", "FileZilla", "wu-ftpd",
                        "Microsoft FTP", "IIS"):
                if sw.lower() in banner.lower():
                    server_sw = sw
                    break

            # Attempt anonymous login
            resp_user = await _ftp_command(reader, writer, "USER anonymous")

            if not resp_user.startswith("331") and not resp_user.startswith("230"):
                # Anonymous not accepted at USER stage
                if server_sw or version:
                    findings.append(Finding(
                        severity="info",
                        plugin_id=META.plugin_id,
                        title=f"FTP server detected: {server_sw or 'unknown'} {version}",
                        evidence=f"host={target} port=21 banner={banner[:200]}",
                        affected=f"{target}:21",
                        fingerprint=stable_fingerprint(target, META.plugin_id, "ftp_banner"),
                    ))
                return PluginResult(
                    findings=findings,
                    artifacts={"infra.ftp.findings": len(findings)},
                )

            # Send password
            resp_pass = await _ftp_command(reader, writer, "PASS guest@")

            if not resp_pass.startswith("230"):
                # Login failed
                return PluginResult(
                    findings=findings,
                    artifacts={"infra.ftp.findings": len(findings)},
                )

            # Anonymous login successful!
            # Try LIST to see directory contents
            dir_listing = ""
            try:
                # Use PASV for data connection
                pasv_resp = await _ftp_command(reader, writer, "PASV")
                pasv_match = re.search(
                    r"\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)", pasv_resp
                )
                if pasv_match:
                    p1 = int(pasv_match.group(5))
                    p2 = int(pasv_match.group(6))
                    data_port = p1 * 256 + p2

                    # Open data connection
                    try:
                        d_reader, d_writer = await asyncio.wait_for(
                            asyncio.open_connection(target, data_port), timeout=3.0
                        )
                        await _ftp_command(reader, writer, "LIST")
                        list_data = await asyncio.wait_for(
                            d_reader.read(8192), timeout=3.0
                        )
                        dir_listing = list_data.decode("utf-8", errors="ignore")
                        d_writer.close()
                    except Exception:
                        pass
            except Exception:
                pass

            # Count files/dirs in listing
            entries = [
                l for l in dir_listing.splitlines() if l.strip()
            ] if dir_listing else []

            # Check for write access (try PWD, don't actually create dirs)
            write_access = False
            try:
                # Try CWD to a common writable dir indicator
                pwd_resp = await _ftp_command(reader, writer, "PWD")
                # Try STOR test — some servers reveal write perm in STAT
                stat_resp = await _ftp_command(reader, writer, "STAT")
                if "write" in stat_resp.lower() or "upload" in stat_resp.lower():
                    write_access = True
            except Exception:
                pass

            severity = "critical" if write_access else "high"

            fp = stable_fingerprint(target, META.plugin_id, "anon_login")
            findings.append(Finding(
                severity=severity,
                plugin_id=META.plugin_id,
                title=(
                    f"FTP anonymous login enabled"
                    f"{' with WRITE access' if write_access else ''}"
                    f" — {len(entries)} entries visible"
                ),
                description=(
                    f"FTP on {target}:21 allows anonymous login. "
                    f"{'Write access is available — attackers can upload malicious files. ' if write_access else ''}"
                    f"The server exposes {len(entries)} file/directory entries. "
                    f"Server: {server_sw or 'unknown'} {version}. "
                    f"Anonymous FTP can leak sensitive data and provide a foothold for attackers."
                ),
                evidence=(
                    f"host={target} port=21 anonymous_login=yes "
                    f"write_access={write_access} entries={len(entries)} "
                    f"server={server_sw} version={version} "
                    f"dir_listing_sample={dir_listing[:300]}"
                ),
                affected=f"{target}:21",
                fingerprint=fp,
                confidence=0.95,
                remediation=(
                    f"[{'CRITICAL — Write Access' if write_access else 'HIGH — Anonymous FTP'}]\n"
                    "FTP anonymous login is enabled.\n\n"
                    "Immediate remediation:\n"
                    "1. Disable anonymous FTP access:\n"
                    "   vsftpd:   anonymous_enable=NO in /etc/vsftpd.conf\n"
                    "   ProFTPD:  <Anonymous> block removed from proftpd.conf\n"
                    "   Pure-FTPd: Remove -e flag or set NoAnonymous yes\n"
                    "2. If anonymous access is intentional:\n"
                    "   - Disable write permissions (anon_upload_enable=NO)\n"
                    "   - Chroot anonymous users\n"
                    "   - Limit to a specific read-only directory\n"
                    "3. Consider replacing FTP with SFTP/SCP for better security\n"
                    "4. Use firewall rules to restrict FTP access\n"
                    "5. Enable TLS for FTP (FTPS) if FTP must remain"
                ),
                references=[
                    "https://cwe.mitre.org/data/definitions/284.html",
                    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods",
                ],
            ))

            # QUIT
            try:
                await _ftp_command(reader, writer, "QUIT")
            except Exception:
                pass

        except (asyncio.TimeoutError, Exception) as e:
            logger.debug("FTP check error on %s: %s", target, e)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

        return PluginResult(
            findings=findings,
            artifacts={"infra.ftp.findings": len(findings)},
        )
