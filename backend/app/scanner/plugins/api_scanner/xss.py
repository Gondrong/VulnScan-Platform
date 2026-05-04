"""
API XSS Scanner
Tests API endpoints for Cross-Site Scripting:
- Reflected XSS in API responses (JSON/HTML)
- Context-aware injection (HTML, attribute, JavaScript)
- WAF bypass payloads
- Polyglot payloads
"""
import asyncio
import logging
import re
import urllib.parse

from app.scanner.plugins.base import Finding
from app.scanner.context import stable_fingerprint

logger = logging.getLogger("vulnscan.api_scanner.xss")

_MARKER = "vScApi_"

_BASIC_PAYLOADS = [
    (f'<script>alert("{_MARKER}1")</script>', f'alert("{_MARKER}1")', "basic_script"),
    (f'<img src=x onerror=alert("{_MARKER}2")>', f'onerror=alert("{_MARKER}2")', "img_onerror"),
    (f'<svg/onload=alert("{_MARKER}3")>', f'onload=alert("{_MARKER}3")', "svg_onload"),
    (f'"><img src=x onerror=alert("{_MARKER}4")>', f'alert("{_MARKER}4")', "attr_break"),
    (f"';alert('{_MARKER}5');//", f"alert('{_MARKER}5')", "js_break"),
    (f'<details open ontoggle=alert("{_MARKER}6")>', f'ontoggle=alert("{_MARKER}6")', "details"),
]

_BYPASS_PAYLOADS = [
    (f'<ScRiPt>alert("{_MARKER}b1")</sCrIpT>', f'alert("{_MARKER}b1")', "case_var"),
    (f'<img src=x onerror=alert`{_MARKER}b2`>', f"alert`{_MARKER}b2`", "template_lit"),
    (f'<svg><animate onbegin=alert("{_MARKER}b3") attributeName=x dur=1s>', f'alert("{_MARKER}b3")', "svg_animate"),
    (f'<math><mtext><img src=x onerror=alert("{_MARKER}b4")>', f'alert("{_MARKER}b4")', "math_nest"),
]

_POLYGLOTS = [
    (f"jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert(\"{_MARKER}p1\") )//", f'alert("{_MARKER}p1")', "polyglot1"),
    (f"'\"-->]]>*/</script><img src=x onerror=alert(\"{_MARKER}p2\")>", f'alert("{_MARKER}p2")', "polyglot2"),
]


async def check(client, endpoints, ctx) -> list[Finding]:
    findings = []
    target = ctx.get("target_raw", "unknown")

    for ep in endpoints[:15]:
        params = [p for p in ep.parameters if p.location in ("query", "body")]
        if not params:
            continue

        for param in params[:3]:
            # Check if input is reflected
            marker = f"{_MARKER}reflect"
            r = await client.send_payload(ep, param.name, marker, param.location)
            if r.status in (0, 404, 405):
                break
            if marker not in r.body:
                continue  # Not reflected, skip

            # Input IS reflected — test payloads
            found = False
            all_payloads = _BASIC_PAYLOADS + _BYPASS_PAYLOADS + _POLYGLOTS

            for payload, check_pat, desc in all_payloads:
                r2 = await client.send_payload(ep, param.name, payload, param.location)
                if r2.status > 0 and check_pat in r2.body:
                    is_bypass = desc.startswith(("case_", "template_", "svg_", "math_", "polyglot"))
                    fp = stable_fingerprint(target, "api.scanner.xss", ep.path, param.name)
                    findings.append(Finding(
                        severity="high", plugin_id="api.scanner.xss",
                        title=f"XSS {'(bypass)' if is_bypass else '(reflected)'}: {ep.method} {ep.path} [{param.name}] — {desc}",
                        description=(
                            f"Reflected XSS in API response. Parameter '{param.name}' at {ep.path} "
                            f"reflects unencoded payload. Technique: {desc}."
                        ),
                        evidence=f"path={ep.path} param={param.name} technique={desc} content_type={r2.content_type}",
                        affected=target, fingerprint=fp, confidence=0.90, cvss=6.1,
                        remediation=(
                            f"[HIGH — CWE-79 / OWASP API8:2023]\n\n"
                            f"[FIX]\n"
                            f"1. HTML-encode all user input in responses\n"
                            f"2. Set Content-Type: application/json (not text/html) for API responses\n"
                            f"3. Add X-Content-Type-Options: nosniff header\n"
                            f"4. Implement Content-Security-Policy"
                        ),
                        references=["https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"],
                    ))
                    found = True
                    break

            if found:
                continue

    return findings
