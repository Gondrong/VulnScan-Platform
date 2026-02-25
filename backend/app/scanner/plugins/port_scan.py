import re

from app.scanner.plugins.base import Finding, Plugin, PluginMeta, PluginResult
from app.scanner.fingerprint import discover_open_ports

META = PluginMeta(
    plugin_id="net.port.discovery.v2",
    name="Port Discovery (V2)",
    category="network",
    provides=["net.open_ports"],
    enabled_by_default=True,
    timeout_seconds=12.0,
)


class Check(Plugin):
    async def run(self, target: str, ctx) -> PluginResult:
        target_raw = ctx.get("target_raw", target)

        # If given a URL, skip TCP port scan (server already responded via HTTP)
        if re.match(r"^https?://", target_raw, re.I):
            scheme = "https" if target_raw.lower().startswith("https") else "http"
            implied_ports = [443] if scheme == "https" else [80]
            return PluginResult(
                findings=[
                    Finding(
                        severity="info",
                        plugin_id=META.plugin_id,
                        title="Port discovery skipped (URL target — implied ports)",
                        evidence=f"target_url={target_raw} implied_ports={implied_ports}",
                        affected=target,
                    )
                ],
                artifacts={"net.open_ports": implied_ports},
            )

        # Normal IP/hostname scan
        ports = await discover_open_ports(target, ctx.policy.timeout_seconds)
        return PluginResult(
            findings=[
                Finding(
                    severity="info",
                    plugin_id=META.plugin_id,
                    title="Open ports discovered",
                    evidence=f"open_ports={ports}",
                    affected=target,
                )
            ],
            artifacts={"net.open_ports": ports},
        )
