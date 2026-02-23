from app.scanner.plugins.base import Plugin, PluginMeta, PluginResult, Finding
from app.scanner.fingerprint import discover_open_ports

META = PluginMeta(
    plugin_id="net.port.discovery.v2",
    name="Port Discovery (V2)",
    category="network",
    provides=["net.open_ports"],
    enabled_by_default=True,
    timeout_seconds=8.0
)

class Check(Plugin):
    async def run(self, target, ctx):
        ports = await discover_open_ports(target, ctx.policy.timeout_seconds)
        return PluginResult(
            findings=[Finding(
                severity="info", plugin_id=META.plugin_id,
                title="Open ports discovered", evidence=str(ports), affected=target
            )],
            artifacts={"net.open_ports": ports}
        )
