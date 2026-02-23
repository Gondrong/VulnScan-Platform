from app.scanner.plugins.base import Plugin, PluginMeta, PluginResult, Finding
from app.scanner.fingerprint import tls_handshake

META = PluginMeta(
    plugin_id="tls.basic.version",
    name="TLS Basic Policy Check",
    category="tls",
    depends_on=["net.port.discovery.v2"],
    consumes=["net.open_ports"],
    provides=["tls.handshake"],
    enabled_by_default=True,
    timeout_seconds=6.0,
)

class Check(Plugin):
    async def run(self, target, ctx):
        ports = ctx.get("net.open_ports", []) or []
        if 443 not in ports and 8443 not in ports:
            return PluginResult()

        p = 443 if 443 in ports else 8443
        try:
            info = tls_handshake(target, p, ctx.policy.timeout_seconds)
            findings=[]
            if info.get("tls_version") in ("TLSv1", "TLSv1.1"):
                findings.append(Finding(
                    severity="medium", plugin_id=META.plugin_id,
                    title="Weak TLS protocol negotiated",
                    description="Server negotiated outdated TLS version",
                    remediation="Disable TLS 1.0/1.1; enforce TLS 1.2/1.3",
                    evidence=str(info), affected=target
                ))
            return PluginResult(findings=findings, artifacts={"tls.handshake": info})
        except Exception as e:
            return PluginResult(findings=[Finding(severity="info", plugin_id=META.plugin_id, title="TLS check failed", evidence=str(e), affected=target)])
