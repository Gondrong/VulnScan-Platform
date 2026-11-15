import asyncio
import re
import urllib.parse

from app.scanner.plugins.base import Plugin, PluginMeta, PluginResult, Finding
from app.scanner.fingerprint import tls_handshake
from app.scanner.context import stable_fingerprint

META = PluginMeta(
    plugin_id="tls.basic.version",
    name="TLS Basic Policy Check",
    category="tls",
    depends_on=["net.port.discovery.v2"],
    consumes=["net.open_ports"],
    provides=["tls.handshake"],
    enabled_by_default=True,
    timeout_seconds=12.0,  # Increased from 6s for external targets
)


def _extract_hostname(target_raw: str, target: str) -> str:
    """Extract proper hostname for SNI from target_raw or target."""
    if re.match(r"^https?://", target_raw, re.I):
        parsed = urllib.parse.urlparse(target_raw)
        return parsed.hostname or target
    return target


class Check(Plugin):
    async def run(self, target, ctx):
        ports = ctx.get("net.open_ports", []) or []
        target_raw = ctx.get("target_raw", target)
        scan_type = ctx.get("scan_type", "internal")

        # For external URL targets, always check TLS on 443
        if scan_type == "external" and re.match(r"^https?://", target_raw, re.I):
            if 443 not in ports:
                ports = list(ports) + [443]

        if 443 not in ports and 8443 not in ports:
            return PluginResult()

        p = 443 if 443 in ports else 8443

        # Use the actual hostname for SNI (not IP or raw target)
        hostname = _extract_hostname(target_raw, target)

        # Longer timeout for external targets
        timeout = ctx.policy.timeout_seconds
        if scan_type == "external":
            timeout = max(timeout, 10.0)

        try:
            # Blocking socket handshake — off the event loop, otherwise the
            # engine's per-plugin asyncio timeout cannot fire.
            info = await asyncio.to_thread(tls_handshake, hostname, p, timeout)
            findings = []

            tls_version = info.get("tls_version", "")
            cipher = info.get("cipher", ())
            not_after = info.get("not_after", "")

            if tls_version in ("TLSv1", "TLSv1.1"):
                findings.append(Finding(
                    severity="medium",
                    plugin_id=META.plugin_id,
                    title=f"Weak TLS protocol: {tls_version}",
                    description=(
                        f"The server negotiated {tls_version}, which is deprecated and has known vulnerabilities "
                        f"(BEAST, POODLE). Modern browsers reject TLS 1.0/1.1 connections."
                    ),
                    remediation=(
                        f"[AFFECTED] TLS version: {tls_version} on port {p}\n\n"
                        "[FIX] Disable TLS 1.0 and TLS 1.1. Enforce TLS 1.2 as minimum, prefer TLS 1.3.\n\n"
                        "[NGINX]\n"
                        "  ssl_protocols TLSv1.2 TLSv1.3;\n"
                        "  ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256';\n\n"
                        "[APACHE]\n"
                        "  SSLProtocol all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1\n\n"
                        "[IIS]\n"
                        "  Disable TLS 1.0/1.1 in Windows Registry or via IIS Crypto tool.\n\n"
                        "[COMPLIANCE] PCI DSS requires TLS 1.2+. NIST recommends TLS 1.2/1.3 only."
                    ),
                    evidence=f"tls_version={tls_version} port={p} cipher={cipher} hostname={hostname}",
                    affected=target,
                    fingerprint=stable_fingerprint(target, META.plugin_id, "weak_tls", tls_version),
                ))
            elif tls_version:
                findings.append(Finding(
                    severity="info",
                    plugin_id=META.plugin_id,
                    title=f"TLS {tls_version} negotiated (acceptable)",
                    description=f"The server uses {tls_version} which meets current security standards.",
                    evidence=f"tls_version={tls_version} port={p} cipher={cipher} hostname={hostname}",
                    affected=target,
                    fingerprint=stable_fingerprint(target, META.plugin_id, "tls_ok", tls_version),
                    remediation=f"TLS {tls_version} is acceptable. For best security, ensure TLS 1.3 is also supported.",
                ))

            # Check cipher strength
            if cipher and len(cipher) >= 2:
                cipher_name = cipher[0] if isinstance(cipher, (list, tuple)) else str(cipher)
                weak_ciphers = ["RC4", "DES", "3DES", "NULL", "EXPORT", "MD5"]
                if any(weak in str(cipher_name).upper() for weak in weak_ciphers):
                    findings.append(Finding(
                        severity="high",
                        plugin_id=META.plugin_id,
                        title=f"Weak TLS cipher suite: {cipher_name}",
                        description="The server negotiated a weak cipher suite that should be disabled.",
                        evidence=f"cipher={cipher} port={p}",
                        affected=target,
                        fingerprint=stable_fingerprint(target, META.plugin_id, "weak_cipher", str(cipher_name)),
                        remediation=(
                            f"[AFFECTED] Weak cipher: {cipher_name}\n\n"
                            "[FIX] Disable weak cipher suites (RC4, DES, 3DES, NULL, EXPORT, MD5-based).\n"
                            "Use only AEAD cipher suites: AES-GCM, ChaCha20-Poly1305.\n\n"
                            "Test your configuration: https://www.ssllabs.com/ssltest/"
                        ),
                    ))

            # Certificate expiry
            if not_after:
                findings.append(Finding(
                    severity="info",
                    plugin_id=META.plugin_id,
                    title=f"TLS certificate expires: {not_after}",
                    evidence=f"not_after={not_after} port={p} subject={info.get('subject', '')} hostname={hostname}",
                    affected=target,
                    fingerprint=stable_fingerprint(target, META.plugin_id, "cert_expiry"),
                    remediation=f"Certificate expires on {not_after}. Ensure automatic renewal is configured (e.g., certbot for Let's Encrypt).",
                ))

            return PluginResult(findings=findings, artifacts={"tls.handshake": info})

        except Exception as e:
            error_msg = str(e)[:256]
            # Provide more helpful error message for common external scan failures
            if "timed out" in error_msg.lower() or "timeout" in error_msg.lower():
                detail = "TLS handshake timed out. The server may be slow or a firewall is filtering port 443."
            elif "refused" in error_msg.lower():
                detail = "Connection refused on port 443. The server may not have HTTPS enabled."
            elif "reset" in error_msg.lower():
                detail = "Connection was reset. A firewall or IPS may be blocking the connection."
            else:
                detail = f"TLS handshake failed: {error_msg}"

            return PluginResult(findings=[Finding(
                severity="info",
                plugin_id=META.plugin_id,
                title="TLS check failed",
                description=detail,
                evidence=f"error={error_msg} hostname={hostname} port={p}",
                affected=target,
                fingerprint=stable_fingerprint(target, META.plugin_id, "error"),
                remediation=(
                    "[AFFECTED] TLS handshake could not be completed\n\n"
                    "[REMEDIATION] Verify the server supports HTTPS on port 443. "
                    "Check firewall rules allow outbound TLS connections. "
                    "If using a non-standard port, configure the scan profile accordingly."
                ),
            )])
