"""
SSL/TLS Grading Plugin
Computes an A-F grade based on TLS protocol version, cipher strength,
certificate validity, and HSTS header presence.

Uses the ssl module for TLS handshake inspection and httpx for HSTS
header checking.
"""
import re
import ssl
import socket
import urllib.parse
from datetime import datetime, timezone

import httpx

from app.scanner.plugins.base import Plugin, PluginMeta, PluginResult, Finding
from app.scanner.context import stable_fingerprint

META = PluginMeta(
    plugin_id="tls.grading",
    name="SSL/TLS Grading",
    category="tls",
    depends_on=["tls.basic.version"],
    consumes=["tls.handshake", "net.open_ports"],
    provides=["tls.grade"],
    enabled_by_default=True,
    timeout_seconds=15.0,
)

# ── Grade boundaries ──────────────────────────────────────────────────
_GRADE_MAP = [
    (95, "A+"),
    (85, "A"),
    (70, "B"),
    (55, "C"),
    (40, "D"),
    (0, "F"),
]

_GRADE_SEVERITY = {
    "A+": "info",
    "A": "info",
    "B": "low",
    "C": "medium",
    "D": "high",
    "F": "critical",
}

# ── AEAD and forward-secrecy cipher keywords ─────────────────────────
_AEAD_KEYWORDS = ["GCM", "CHACHA20", "POLY1305", "CCM"]
_FS_KEYWORDS = ["ECDHE", "DHE", "ECDH"]
_WEAK_KEYWORDS = ["RC4", "DES", "3DES", "NULL", "EXPORT", "MD5", "anon"]


def _compute_grade(score: int) -> str:
    """Map a numeric score (0-100) to a letter grade."""
    for threshold, grade in _GRADE_MAP:
        if score >= threshold:
            return grade
    return "F"


def _perform_tls_check(hostname: str, port: int, timeout: float = 8.0) -> dict:
    """
    Perform a TLS handshake and extract protocol, cipher, and cert info.
    Returns a dict with keys: tls_version, cipher_name, cipher_bits,
    is_aead, has_fs, has_weak, cert_valid, cert_self_signed,
    cert_expires, days_until_expiry.
    """
    result = {
        "tls_version": None,
        "cipher_name": None,
        "cipher_bits": 0,
        "is_aead": False,
        "has_fs": False,
        "has_weak": False,
        "cert_valid": False,
        "cert_self_signed": False,
        "cert_expires": None,
        "days_until_expiry": None,
        "subject": None,
        "issuer": None,
    }

    # First attempt: permissive context to get cipher/protocol info
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    # Enable all protocols for detection
    ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED

    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                result["tls_version"] = ssock.version()
                cipher_info = ssock.cipher()
                if cipher_info:
                    result["cipher_name"] = cipher_info[0]
                    result["cipher_bits"] = cipher_info[2] if len(cipher_info) > 2 else 0

                # Get certificate info (unverified)
                cert = ssock.getpeercert(binary_form=False)
                if not cert:
                    # Try binary form for DER
                    der_cert = ssock.getpeercert(binary_form=True)
                    if der_cert:
                        result["cert_valid"] = False
                else:
                    # Extract cert details
                    not_after = cert.get("notAfter", "")
                    if not_after:
                        try:
                            expiry = datetime.strptime(
                                not_after, "%b %d %H:%M:%S %Y %Z"
                            ).replace(tzinfo=timezone.utc)
                            result["cert_expires"] = not_after
                            result["days_until_expiry"] = (
                                expiry - datetime.now(timezone.utc)
                            ).days
                        except Exception:
                            pass

                    subject = dict(
                        x[0] for x in cert.get("subject", ()) if x
                    )
                    issuer = dict(
                        x[0] for x in cert.get("issuer", ()) if x
                    )
                    result["subject"] = subject.get("commonName", "")
                    result["issuer"] = issuer.get("organizationName", "")

                    # Check self-signed
                    if subject == issuer:
                        result["cert_self_signed"] = True
    except Exception:
        return result

    # Analyze cipher characteristics
    cipher_upper = (result["cipher_name"] or "").upper()
    result["is_aead"] = any(kw in cipher_upper for kw in _AEAD_KEYWORDS)
    result["has_fs"] = any(kw in cipher_upper for kw in _FS_KEYWORDS)
    result["has_weak"] = any(kw in cipher_upper for kw in _WEAK_KEYWORDS)

    # Second attempt: strict context to check certificate validity
    try:
        strict_ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with strict_ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                result["cert_valid"] = True
    except ssl.SSLCertVerificationError:
        result["cert_valid"] = False
    except Exception:
        # Connection issues - don't mark cert as invalid
        pass

    return result


class Check(Plugin):
    async def run(self, target: str, ctx) -> PluginResult:
        ports = ctx.get("net.open_ports", []) or []
        tls_data = ctx.get("tls.handshake", {}) or {}
        target_raw = ctx.get("target_raw", target)

        # Determine hostname and port
        hostname = target
        if re.match(r"^https?://", target_raw, re.I):
            parsed = urllib.parse.urlparse(target_raw)
            hostname = parsed.hostname or target

        # Find the TLS port
        tls_port = None
        if 443 in ports:
            tls_port = 443
        elif 8443 in ports:
            tls_port = 8443
        else:
            # Check if any common TLS port is open
            for p in [443, 8443, 4443]:
                if p in ports:
                    tls_port = p
                    break

        if tls_port is None:
            return PluginResult(artifacts={"tls.grade": {}})

        # Perform the TLS check
        try:
            tls_info = _perform_tls_check(
                hostname, tls_port,
                timeout=min(ctx.policy.timeout_seconds, 8.0)
            )
        except Exception:
            return PluginResult(
                findings=[Finding(
                    severity="info",
                    plugin_id=META.plugin_id,
                    title="TLS grading failed - could not complete handshake",
                    evidence=f"hostname={hostname} port={tls_port}",
                    affected=target,
                    fingerprint=stable_fingerprint(
                        target, META.plugin_id, "error"
                    ),
                    remediation=(
                        "TLS handshake could not be completed for grading. "
                        "Verify the server supports TLS on the target port."
                    ),
                )],
                artifacts={"tls.grade": {}},
            )

        if not tls_info.get("tls_version"):
            return PluginResult(
                findings=[Finding(
                    severity="info",
                    plugin_id=META.plugin_id,
                    title="TLS grading skipped - no TLS version detected",
                    evidence=f"hostname={hostname} port={tls_port}",
                    affected=target,
                    fingerprint=stable_fingerprint(
                        target, META.plugin_id, "no_tls"
                    ),
                    remediation="No TLS version could be negotiated. The server may not support TLS.",
                )],
                artifacts={"tls.grade": {}},
            )

        # ── Compute score ─────────────────────────────────────────────
        score = 0
        score_breakdown = []
        tls_ver = tls_info["tls_version"] or ""

        # TLS version scoring
        if "1.3" in tls_ver:
            score += 30
            score_breakdown.append("TLS 1.3 support: +30")
        elif "1.2" in tls_ver:
            score += 20
            score_breakdown.append("TLS 1.2 only: +20")

        if "1.1" in tls_ver or "1.0" in tls_ver or "SSLv" in tls_ver:
            score -= 40
            score_breakdown.append(f"Legacy protocol ({tls_ver}): -40")

        # Cipher scoring
        if tls_info["is_aead"]:
            score += 20
            score_breakdown.append("AEAD cipher (GCM/ChaCha20): +20")

        if tls_info["has_fs"]:
            score += 20
            score_breakdown.append("Forward secrecy (ECDHE/DHE): +20")

        if tls_info["has_weak"]:
            score -= 30
            score_breakdown.append(f"Weak cipher ({tls_info['cipher_name']}): -30")

        # Certificate scoring
        if tls_info["cert_valid"] and not tls_info["cert_self_signed"]:
            score += 10
            score_breakdown.append("Valid certificate: +10")
        elif tls_info["cert_self_signed"]:
            score_breakdown.append("Self-signed certificate: +0")
        else:
            score_breakdown.append("Invalid certificate: +0")

        # Certificate expiry penalty
        days = tls_info.get("days_until_expiry")
        if days is not None and days < 30:
            score -= 10
            score_breakdown.append(f"Certificate expiring in {days} days: -10")

        # HSTS check via HTTP request
        hsts_present = False
        try:
            async with httpx.AsyncClient(
                timeout=min(ctx.policy.timeout_seconds, 6),
                verify=False,
                follow_redirects=True,
                limits=httpx.Limits(max_connections=2),
            ) as client:
                r = await client.get(f"https://{hostname}:{tls_port}/")
                hsts_val = r.headers.get("strict-transport-security", "")
                if hsts_val:
                    hsts_present = True
        except Exception:
            pass

        if hsts_present:
            score += 10
            score_breakdown.append("HSTS header present: +10")
        else:
            score_breakdown.append("HSTS header missing: +0")

        # Clamp score
        score = max(0, min(100, score))
        grade = _compute_grade(score)
        severity = _GRADE_SEVERITY.get(grade, "medium")

        # Build detailed evidence
        evidence_parts = [
            f"grade={grade}",
            f"score={score}",
            f"tls_version={tls_ver}",
            f"cipher={tls_info['cipher_name']}",
            f"bits={tls_info['cipher_bits']}",
            f"aead={tls_info['is_aead']}",
            f"forward_secrecy={tls_info['has_fs']}",
            f"cert_valid={tls_info['cert_valid']}",
            f"self_signed={tls_info['cert_self_signed']}",
            f"hsts={hsts_present}",
        ]
        if days is not None:
            evidence_parts.append(f"cert_days_remaining={days}")

        fp = stable_fingerprint(target, META.plugin_id, "grade", grade)

        # Build remediation based on score breakdown
        remediation_lines = [
            f"[TLS GRADE] {grade} ({score}/100)\n",
            "[SCORE BREAKDOWN]",
        ]
        for item in score_breakdown:
            remediation_lines.append(f"  {item}")

        remediation_lines.append("")

        if score < 85:
            remediation_lines.append("[RECOMMENDED IMPROVEMENTS]")
            if "1.3" not in tls_ver:
                remediation_lines.append(
                    "  - Enable TLS 1.3 for best security and performance"
                )
            if not tls_info["is_aead"]:
                remediation_lines.append(
                    "  - Configure AEAD cipher suites (AES-GCM, ChaCha20-Poly1305)"
                )
            if not tls_info["has_fs"]:
                remediation_lines.append(
                    "  - Enable forward secrecy (ECDHE key exchange)"
                )
            if tls_info["has_weak"]:
                remediation_lines.append(
                    f"  - Disable weak cipher: {tls_info['cipher_name']}"
                )
            if not tls_info["cert_valid"]:
                remediation_lines.append(
                    "  - Obtain a valid certificate from a trusted CA "
                    "(e.g., Let's Encrypt)"
                )
            if not hsts_present:
                remediation_lines.append(
                    "  - Add HSTS header: Strict-Transport-Security: "
                    "max-age=31536000; includeSubDomains"
                )
            if days is not None and days < 30:
                remediation_lines.append(
                    f"  - Certificate expires in {days} days — renew immediately"
                )
            remediation_lines.append("")
            remediation_lines.append(
                "[TEST] https://www.ssllabs.com/ssltest/"
            )

        findings = [Finding(
            severity=severity,
            plugin_id=META.plugin_id,
            title=f"TLS Grade: {grade} ({score}/100) — {hostname}:{tls_port}",
            description=(
                f"SSL/TLS configuration graded {grade} ({score}/100). "
                f"Protocol: {tls_ver}, Cipher: {tls_info['cipher_name']}, "
                f"Forward secrecy: {'Yes' if tls_info['has_fs'] else 'No'}, "
                f"AEAD: {'Yes' if tls_info['is_aead'] else 'No'}, "
                f"Certificate valid: {'Yes' if tls_info['cert_valid'] else 'No'}, "
                f"HSTS: {'Yes' if hsts_present else 'No'}."
            ),
            evidence=" ".join(evidence_parts),
            affected=target,
            fingerprint=fp,
            confidence=0.90,
            remediation="\n".join(remediation_lines),
            references=[
                "https://www.ssllabs.com/ssltest/",
                "https://wiki.mozilla.org/Security/Server_Side_TLS",
            ],
        )]

        grade_artifact = {
            "grade": grade,
            "score": score,
            "tls_version": tls_ver,
            "cipher": tls_info["cipher_name"],
            "cipher_bits": tls_info["cipher_bits"],
            "forward_secrecy": tls_info["has_fs"],
            "aead": tls_info["is_aead"],
            "cert_valid": tls_info["cert_valid"],
            "self_signed": tls_info["cert_self_signed"],
            "cert_expires": tls_info["cert_expires"],
            "days_until_expiry": days,
            "hsts": hsts_present,
            "hostname": hostname,
            "port": tls_port,
            "breakdown": score_breakdown,
        }

        return PluginResult(
            findings=findings,
            artifacts={"tls.grade": grade_artifact},
        )
