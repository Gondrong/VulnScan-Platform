import re

from app.scanner.plugins.base import Finding, Plugin, PluginMeta, PluginResult
from app.scanner.fingerprint import discover_open_ports

META = PluginMeta(
    plugin_id="net.port.discovery.v2",
    name="Port Discovery (V2)",
    category="network",
    provides=["net.open_ports"],
    enabled_by_default=True,
    timeout_seconds=30.0,  # External targets need more time (firewalled ports cause full waits)
)


class Check(Plugin):
    async def run(self, target: str, ctx) -> PluginResult:
        target_raw = ctx.get("target_raw", target)
        scan_type = ctx.get("scan_type", "internal")

        # If given a URL, skip TCP port scan — use implied ports from the URL scheme
        if re.match(r"^https?://", target_raw, re.I):
            scheme = "https" if target_raw.lower().startswith("https") else "http"
            implied_ports = [443] if scheme == "https" else [80]
            # Also include the other common web port
            if 443 not in implied_ports:
                implied_ports.append(443)
            if 80 not in implied_ports:
                implied_ports.append(80)
            implied_ports.sort()

            return PluginResult(
                findings=[
                    Finding(
                        severity="info",
                        plugin_id=META.plugin_id,
                        title=f"URL target — using implied ports {implied_ports}",
                        evidence=f"target_url={target_raw} implied_ports={implied_ports}",
                        affected=target,
                        remediation="URL targets use implied web ports. To scan additional ports, use an IP/hostname target instead.",
                    )
                ],
                artifacts={"net.open_ports": implied_ports},
            )

        # For external scan type with a domain, assume web ports and try discovery
        if scan_type == "external" and not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", target):
            web_ports = [80, 443]
            try:
                additional = await discover_open_ports(target, ctx.policy.timeout_seconds)
                all_ports = sorted(set(web_ports + additional))
            except Exception:
                all_ports = web_ports

            return PluginResult(
                findings=[
                    Finding(
                        severity="info",
                        plugin_id=META.plugin_id,
                        title=f"External scan: {len(all_ports)} ports discovered",
                        evidence=f"open_ports={all_ports} scan_type=external target={target}",
                        affected=target,
                        remediation="Review open ports and ensure only necessary services are exposed to the internet.",
                    )
                ],
                artifacts={"net.open_ports": all_ports},
            )

        # Normal IP/hostname scan
        ports = await discover_open_ports(target, ctx.policy.timeout_seconds)
        return PluginResult(
            findings=[
                Finding(
                    severity="info",
                    plugin_id=META.plugin_id,
                    title=f"Open ports discovered ({len(ports)} found)",
                    evidence=f"open_ports={ports}",
                    affected=target,
                    remediation="Review all open ports and ensure only necessary services are running. Disable or firewall-block unused ports." if ports else "No open ports found on common service ports.",
                )
            ],
            artifacts={"net.open_ports": ports},
        )
