"""
Authenticated SSH Inventory plugin.
Connects to the target via SSH, collects OS and package information.
"""
import re
from app.scanner.plugins.base import Plugin, PluginMeta, PluginResult, Finding
from app.db.session import SessionLocal
from app.db import models
from app.scanner.ssh_client import ssh_inventory
from app.scanner.context import stable_fingerprint

META = PluginMeta(
    plugin_id="auth.ssh.inventory",
    name="Authenticated SSH Inventory",
    category="authenticated",
    depends_on=["net.port.discovery.v2"],
    consumes=["net.open_ports"],
    provides=["inventory.os", "inventory.packages"],
    enabled_by_default=False,
    timeout_seconds=30.0,  # SSH needs more time than 12s
)


def parse_os_release(text: str) -> dict:
    out = {}
    for line in (text or "").splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip().strip('"')
    return out


def parse_dpkg(text: str):
    pkgs = []
    for line in (text or "").splitlines():
        parts = line.split("\t")
        if len(parts) == 2:
            pkgs.append({"name": parts[0].strip(), "version": parts[1].strip(), "ecosystem": "deb"})
    return pkgs


def parse_rpm(text: str):
    pkgs = []
    for line in (text or "").splitlines():
        parts = line.split("\t")
        if len(parts) == 2:
            pkgs.append({"name": parts[0].strip(), "version": parts[1].strip(), "ecosystem": "rpm"})
    return pkgs


def parse_apk(text: str):
    pkgs = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        pkgs.append({"name": line.split("-", 1)[0], "version": line, "ecosystem": "apk"})
    return pkgs


class Check(Plugin):
    async def run(self, target, ctx):
        ports = ctx.get("net.open_ports", []) or []
        if 22 not in ports:
            return PluginResult()

        opt = ctx.get("profile_options", {}) or {}
        auth = opt.get("auth", {}) or {}
        cred_id = auth.get("ssh_credential_id")
        ssh_port = int(auth.get("ssh_port", 22))

        if not cred_id:
            return PluginResult(findings=[Finding(
                severity="info",
                plugin_id=META.plugin_id,
                title="SSH inventory skipped — no credential configured",
                description=(
                    "The scan profile has auth.ssh.inventory enabled but no "
                    "ssh_credential_id is set in the profile options. "
                    "Go to Profiles → Scan Options → SSH Credential to select one."
                ),
                evidence="ssh_credential_id=None",
                affected=target,
                fingerprint=stable_fingerprint(target, META.plugin_id, "no_cred_configured"),
            )])

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

            if not cred:
                # List available credentials to help the user
                avail = db.query(models.Credential).filter(
                    models.Credential.workspace_id == ws_id
                ).all()
                avail_str = ", ".join(
                    f"#{c.id} ({c.name})" for c in avail
                ) if avail else "none — add one in Credentials page"

                return PluginResult(findings=[Finding(
                    severity="medium",
                    plugin_id=META.plugin_id,
                    title=f"SSH credential #{cred_id} not found",
                    description=(
                        f"The scan profile references credential ID #{cred_id} but it "
                        f"doesn't exist in this workspace. Available credentials: {avail_str}. "
                        f"Update the profile's SSH Credential dropdown to match an existing credential."
                    ),
                    evidence=f"requested_id={cred_id} available=[{avail_str}]",
                    affected=target,
                    fingerprint=stable_fingerprint(target, META.plugin_id, "cred_not_found", str(cred_id)),
                )])

            # Attempt SSH connection and inventory
            raw = ssh_inventory(
                target,
                ssh_port,
                cred.username,
                cred.secret_type,
                cred.secret_enc,
                cred.passphrase_enc,
                ctx.policy.timeout_seconds,
            )

            osinfo = parse_os_release(raw.get("os_release", ""))
            pkgs = (
                parse_dpkg(raw.get("dpkg", ""))
                + parse_rpm(raw.get("rpm", ""))
                + parse_apk(raw.get("apk", ""))
            )

            os_name = osinfo.get("PRETTY_NAME") or osinfo.get("NAME", "unknown")
            uname = raw.get("uname", "")

            return PluginResult(
                findings=[Finding(
                    severity="info",
                    plugin_id=META.plugin_id,
                    title=f"SSH inventory collected ({os_name}, {len(pkgs)} packages)",
                    evidence=f"os={os_name} uname={uname[:80]} packages={len(pkgs)}",
                    affected=target,
                    fingerprint=stable_fingerprint(target, META.plugin_id, "success"),
                )],
                artifacts={
                    "inventory.os": {
                        "os_release": osinfo,
                        "uname": uname,
                    },
                    "inventory.packages": pkgs,
                },
            )

        except Exception as e:
            err_msg = str(e)
            # Provide specific remediation based on error type
            if "authentication failed" in err_msg.lower():
                remediation = (
                    "Check that the SSH username and key/password are correct. "
                    "Verify the key type matches what the server accepts (ssh -v user@host). "
                    "Ensure the user has SSH access on the target."
                )
            elif "timed out" in err_msg.lower() or "timeout" in err_msg.lower():
                remediation = (
                    "SSH connection timed out. Check that port 22 is open and not firewalled. "
                    "Try increasing SCAN_TIMEOUT_SECONDS in your .env file."
                )
            elif "unable to parse" in err_msg.lower() or "key" in err_msg.lower():
                remediation = (
                    "The SSH key format may not be supported. Ensure the key is in OpenSSH or PEM format. "
                    "Try regenerating with: ssh-keygen -t ed25519 -f mykey"
                )
            else:
                remediation = f"SSH connection failed: {err_msg}"

            return PluginResult(findings=[Finding(
                severity="medium",
                plugin_id=META.plugin_id,
                title="SSH inventory failed",
                description=remediation,
                evidence=err_msg[:512],
                affected=target,
                fingerprint=stable_fingerprint(target, META.plugin_id, "failed"),
            )])
        finally:
            db.close()
