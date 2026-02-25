import re

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
    timeout_seconds=10.0,
)


class Check(Plugin):
    async def run(self, target: str, ctx) -> PluginResult:
        ports = ctx.get("net.open_ports", []) or []
        target_raw = ctx.get("target_raw", target)
        scheme = ctx.get("target_scheme", "unknown")
        out = []

        # If target is a full URL, do a direct HTTP request
        if re.match(r"^https?://", target_raw, re.I):
            tls = target_raw.lower().startswith("https://")
            try:
                result = await http_fingerprint(
                    target_raw, ctx.policy.timeout_seconds, 443 if tls else 80, tls
                )
                out.append(result)
            except Exception as e:
                pass
        else:
            # IP/hostname — check discovered ports
            http_port_map = {
                80: False,
                8080: False,
                443: True,
                8443: True,
                9200: False,
            }
            for p, tls in http_port_map.items():
                if p in ports:
                    try:
                        result = await http_fingerprint(
                            target, ctx.policy.timeout_seconds, p, tls
                        )
                        out.append(result)
                    except Exception:
                        pass

        return PluginResult(
            findings=[],
            artifacts={"fingerprint.http": {"http": out}},
        )
