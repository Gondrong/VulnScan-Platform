import re
import asyncio

from app.scanner.plugins.base import Plugin, PluginMeta, PluginResult, Finding
from app.scanner.fingerprint import http_fingerprint
from app.scanner.context import stable_fingerprint

META = PluginMeta(
    plugin_id="fingerprint.http",
    name="HTTP Fingerprint",
    category="fingerprint",
    depends_on=["net.port.discovery.v2"],
    consumes=["net.open_ports"],
    provides=["fingerprint.http"],
    enabled_by_default=True,
    timeout_seconds=30.0,
)


def _add_header_findings(findings, result, target, url, plugin_id, port=None):
    server = result.get("server", "")
    powered_by = result.get("powered_by", "")
    status = result.get("status", "?")
    port_str = f" on port {port}" if port else ""

    if server:
        # Server header version disclosure aids attacker recon
        findings.append(Finding(
            severity="low",
            plugin_id=plugin_id,
            title=f"HTTP Server header disclosed{port_str}: {server}",
            description=f"The web server at {url} reveals its software version in the Server header (status {status}).",
            evidence=f"server={server} url={result.get('url', url)} status={status}",
            affected=target,
            fingerprint=stable_fingerprint(target, plugin_id, "server", server, str(port or "")),
            remediation=(
                f"[AFFECTED] Server header reveals: {server}\n\n"
                "[REMEDIATION] Suppress version information:\n"
                "  nginx: server_tokens off;\n"
                "  Apache: ServerTokens Prod / ServerSignature Off\n"
                "  IIS: Use URL Rewrite to remove Server header"
            ),
        ))

    if powered_by:
        findings.append(Finding(
            severity="low",
            plugin_id=plugin_id,
            title=f"X-Powered-By header disclosed{port_str}: {powered_by}",
            description="The target reveals its backend technology via X-Powered-By header.",
            evidence=f"x-powered-by={powered_by} url={result.get('url', url)}",
            affected=target,
            fingerprint=stable_fingerprint(target, plugin_id, "powered_by", powered_by, str(port or "")),
            remediation=(
                f"[AFFECTED] X-Powered-By reveals: {powered_by}\n\n"
                "[REMEDIATION] Remove this header:\n"
                "  PHP: set expose_php = Off in php.ini\n"
                "  Express.js: app.disable('x-powered-by')\n"
                "  ASP.NET: <customHeaders><remove name='X-Powered-By'/></customHeaders>"
            ),
        ))


class Check(Plugin):
    async def run(self, target: str, ctx) -> PluginResult:
        ports = ctx.get("net.open_ports", []) or []
        target_raw = ctx.get("target_raw", target)
        scan_type = ctx.get("scan_type", "internal")
        out = []
        findings = []

        # Use the engine's effective timeout to cap HTTP requests, so we
        # don't make an httpx request that outlives the engine's kill timer.
        effective = ctx.get("_effective_timeout", ctx.policy.timeout_seconds)
        base_timeout = min(ctx.policy.timeout_seconds, effective)
        if scan_type == "external":
            base_timeout = max(base_timeout, 10.0)

        if re.match(r"^https?://", target_raw, re.I):
            tls = target_raw.lower().startswith("https://")
            port = 443 if tls else 80

            try:
                result = await http_fingerprint(target_raw, base_timeout, port, tls)
                out.append(result)
                _add_header_findings(findings, result, target, target_raw, META.plugin_id)
            except asyncio.TimeoutError:
                findings.append(Finding(
                    severity="info", plugin_id=META.plugin_id,
                    title=f"HTTP fingerprint timed out for {target_raw}",
                    evidence=f"timeout={base_timeout}s url={target_raw}",
                    affected=target,
                    fingerprint=stable_fingerprint(target, META.plugin_id, "timeout"),
                    remediation="HTTP connection timed out. Try increasing SCAN_TIMEOUT_SECONDS in .env.",
                ))
            except Exception as e:
                findings.append(Finding(
                    severity="info", plugin_id=META.plugin_id,
                    title=f"HTTP fingerprint failed for {target_raw}",
                    evidence=f"error={str(e)[:256]} url={target_raw}",
                    affected=target,
                    fingerprint=stable_fingerprint(target, META.plugin_id, "error", str(e)[:64]),
                    remediation="Could not connect. Verify the URL is correct and the server is accessible.",
                ))

            # Try alternate protocol
            alt_tls = not tls
            alt_port = 80 if tls else 443
            alt_url = target_raw.replace("https://", "http://") if tls else target_raw.replace("http://", "https://")
            try:
                r2 = await http_fingerprint(alt_url, min(base_timeout, 5.0), alt_port, alt_tls)
                out.append(r2)
                _add_header_findings(findings, r2, target, alt_url, META.plugin_id)
            except Exception:
                pass

        else:
            http_port_map = {80: False, 8080: False, 443: True, 8443: True, 9200: False}

            if scan_type == "external":
                # For external targets with 0 discovered ports, do a quick TCP
                # reachability check before force-probing 80/443 — avoids wasting
                # the entire plugin timeout on a completely firewalled host.
                if not ports:
                    from app.scanner.fingerprint import tcp_open
                    probe_timeout = min(base_timeout / 3, 8.0)
                    r80, r443 = await asyncio.gather(
                        tcp_open(target, 80, probe_timeout),
                        tcp_open(target, 443, probe_timeout),
                        return_exceptions=True,
                    )
                    reachable = []
                    if r80 is True:
                        reachable.append(80)
                    if r443 is True:
                        reachable.append(443)
                    if not reachable:
                        return PluginResult(
                            findings=[Finding(
                                severity="info",
                                plugin_id=META.plugin_id,
                                title="No HTTP services reachable on target",
                                evidence=f"tcp_probe_timeout={probe_timeout:.1f}s ports_tested=[80,443] target={target}",
                                affected=target,
                                fingerprint=stable_fingerprint(target, META.plugin_id, "unreachable"),
                                remediation="Target does not respond on ports 80 or 443. It may be firewalled or offline.",
                            )],
                            artifacts={"http.fingerprints": []},
                        )
                    ports = reachable
                else:
                    for p in [80, 443]:
                        if p not in ports:
                            ports = list(ports) + [p]

            for p, tls in http_port_map.items():
                if p not in ports:
                    continue
                try:
                    scheme = "https" if tls else "http"
                    url = f"{scheme}://{target}:{p}" if p not in (80, 443) else f"{scheme}://{target}"
                    result = await http_fingerprint(url, base_timeout, p, tls)
                    out.append(result)
                    _add_header_findings(findings, result, target, url, META.plugin_id, p)
                except asyncio.TimeoutError:
                    if scan_type == "external":
                        findings.append(Finding(
                            severity="info", plugin_id=META.plugin_id,
                            title=f"HTTP fingerprint timed out on port {p}",
                            evidence=f"timeout={base_timeout}s port={p} target={target}",
                            affected=target,
                            fingerprint=stable_fingerprint(target, META.plugin_id, "timeout", str(p)),
                            remediation=f"Connection to port {p} timed out. The port may be filtered.",
                        ))
                except Exception:
                    pass

        return PluginResult(
            findings=findings,
            artifacts={"fingerprint.http": {"http": out}},
        )
