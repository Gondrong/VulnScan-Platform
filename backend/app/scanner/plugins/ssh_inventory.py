import re
from app.scanner.plugins.base import Plugin, PluginMeta, PluginResult, Finding
from app.db.session import SessionLocal
from app.db import models
from app.scanner.ssh_client import ssh_inventory

META = PluginMeta(
    plugin_id="auth.ssh.inventory",
    name="Authenticated SSH Inventory",
    category="authenticated",
    depends_on=["net.port.discovery.v2"],
    consumes=["net.open_ports"],
    provides=["inventory.os","inventory.packages"],
    enabled_by_default=False,
    timeout_seconds=12.0,
)

def parse_os_release(text: str) -> dict:
    out={}
    for line in (text or "").splitlines():
        if "=" in line:
            k,v=line.split("=",1)
            out[k.strip()] = v.strip().strip('"')
    return out

def parse_dpkg(text: str):
    pkgs=[]
    for line in (text or "").splitlines():
        parts=line.split("\t")
        if len(parts)==2:
            pkgs.append({"name":parts[0].strip(),"version":parts[1].strip(),"ecosystem":"deb"})
    return pkgs

def parse_rpm(text: str):
    pkgs=[]
    for line in (text or "").splitlines():
        parts=line.split("\t")
        if len(parts)==2:
            pkgs.append({"name":parts[0].strip(),"version":parts[1].strip(),"ecosystem":"rpm"})
    return pkgs

def parse_apk(text: str):
    pkgs=[]
    for line in (text or "").splitlines():
        line=line.strip()
        if not line: continue
        pkgs.append({"name":line.split("-",1)[0],"version":line,"ecosystem":"apk"})
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
            return PluginResult()

        db = SessionLocal()
        try:
            cred = db.query(models.Credential).filter(models.Credential.id==cred_id, models.Credential.workspace_id==ctx.get("workspace_id")).first()
            if not cred:
                return PluginResult(findings=[Finding(severity="info", plugin_id=META.plugin_id, title="SSH credential not found", evidence=str(cred_id), affected=target)])

            raw = ssh_inventory(target, ssh_port, cred.username, cred.secret_type, cred.secret_enc, cred.passphrase_enc, ctx.policy.timeout_seconds)
            osinfo = parse_os_release(raw.get("os_release",""))
            pkgs = parse_dpkg(raw.get("dpkg","")) + parse_rpm(raw.get("rpm","")) + parse_apk(raw.get("apk",""))

            return PluginResult(
                findings=[Finding(severity="info", plugin_id=META.plugin_id, title="SSH inventory collected", evidence=f"os={osinfo.get('NAME','')} pkgs={len(pkgs)}", affected=target)],
                artifacts={"inventory.os": {"os_release": osinfo, "uname": raw.get("uname","")}, "inventory.packages": pkgs}
            )
        except Exception as e:
            return PluginResult(findings=[Finding(severity="info", plugin_id=META.plugin_id, title="SSH inventory failed", evidence=str(e), affected=target)])
        finally:
            db.close()
