from app.scanner.plugins.base import Plugin, PluginMeta, PluginResult
from app.scanner.fingerprint import http_fingerprint

META = PluginMeta(
    plugin_id="fingerprint.http",
    name="HTTP Fingerprint",
    category="fingerprint",
    depends_on=["net.port.discovery.v2"],
    consumes=["net.open_ports"],
    provides=["fingerprint.http"],
    enabled_by_default=True,
    timeout_seconds=8.0,
)

class Check(Plugin):
    async def run(self, target, ctx):
        ports = ctx.get("net.open_ports", []) or []
        http_ports = [p for p in ports if p in (80,8080,443,8443,9200)]
        out=[]
        for p in http_ports:
            tls = p in (443,8443)
            try:
                out.append(await http_fingerprint(target, ctx.policy.timeout_seconds, p, tls))
            except:
                pass
        return PluginResult(findings=[], artifacts={"fingerprint.http": {"http": out}})
