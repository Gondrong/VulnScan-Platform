import asyncio, ssl, socket
from app.scanner.plugins.base import Plugin, PluginMeta, PluginResult, Finding
from app.scanner.context import stable_fingerprint

META = PluginMeta(
    plugin_id="fingerprint.banner.multi",
    name="Multi-Protocol Banner Grabber",
    category="fingerprint",
    depends_on=["net.port.discovery.v2"],
    consumes=["net.open_ports"],
    provides=["fingerprint.banners"],
    enabled_by_default=True,
    timeout_seconds=5.0,
)

async def grab_tcp(host, port, payload=None, timeout=3.0):
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        if payload:
            w.write(payload); await w.drain()
        data = await asyncio.wait_for(r.read(1024), timeout=timeout)
        w.close(); await w.wait_closed()
        return data.decode("utf-8", errors="ignore").strip()
    except:
        return ""

def tls_cert(host, port, timeout=3.0):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                return {"subject": ssock.getpeercert().get("subject", []), "version": ssock.version()}
    except:
        return None

BANNER_REMEDIATION = {
    22: "SSH banner reveals version info. Configure 'Banner none' in sshd_config to suppress. Keep OpenSSH updated.",
    21: "FTP banner reveals server info. Consider disabling FTP in favor of SFTP. If FTP is required, suppress the banner.",
    25: "SMTP banner reveals mail server info. Configure your MTA to show a generic banner.",
    6379: "Redis is accessible on the network. Ensure Redis is bound to localhost only (bind 127.0.0.1), enable AUTH, and disable dangerous commands.",
    9200: "Elasticsearch is accessible. Enable X-Pack security, configure TLS, and restrict network access.",
}

class Check(Plugin):
    async def run(self, target, ctx):
        ports = ctx.get("net.open_ports", []) or []
        banners=[]
        tls=[]
        findings=[]
        for p in ports:
            b=""
            if p==22: b = await grab_tcp(target, p)
            elif p==21: b = await grab_tcp(target, p)
            elif p==25: b = await grab_tcp(target, p)
            elif p==6379: b = await grab_tcp(target, p, b"INFO\r\n")
            elif p==9200: b = await grab_tcp(target, p, b"GET / HTTP/1.0\r\n\r\n")
            if b:
                banners.append({"port":p,"banner":b})
                findings.append(Finding(
                    severity="medium" if p in (6379, 9200) else "low",
                    plugin_id=META.plugin_id,
                    title=f"Service banner on port {p}",
                    description=f"Service on port {p} discloses a banner with potentially sensitive version information.",
                    evidence=f"port={p} banner={b[:200]}",
                    affected=target,
                    fingerprint=stable_fingerprint(target, META.plugin_id, str(p), b[:64]),
                    remediation=BANNER_REMEDIATION.get(p, f"Review the service on port {p} and suppress version disclosure in the service banner. Keep the service updated to the latest version."),
                ))
            if p in (443,8443):
                c = await asyncio.get_event_loop().run_in_executor(None, tls_cert, target, p)
                if c: tls.append({"port":p,"cert":c})
        return PluginResult(findings=findings, artifacts={"fingerprint.banners": {"banners":banners, "tls_certs":tls}})