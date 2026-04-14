"""
API Server-Side Template Injection (SSTI) Scanner
Detects SSTI across multiple template engines:
Jinja2, Twig, Freemarker, Pebble, Mako, Velocity, Smarty, ERB, Jade/Pug
"""
import asyncio
import logging
import re

from app.scanner.plugins.base import Finding
from app.scanner.context import stable_fingerprint

logger = logging.getLogger("vulnscan.api_scanner.ssti")

# Math-based detection: inject expression, check if result appears
_SSTI_PAYLOADS = [
    # Jinja2 / Twig (Python/PHP)
    ("{{7*7}}", "49", "jinja2/twig", "high"),
    ("{{7*'7'}}", "7777777", "jinja2", "high"),
    ("${7*7}", "49", "freemarker/velocity", "high"),
    ("#{7*7}", "49", "pebble/thymeleaf", "high"),
    ("<%= 7*7 %>", "49", "erb/jsp", "high"),
    ("{{config}}", "SECRET_KEY", "jinja2_config", "critical"),
    ("{{self.__class__}}", "__class__", "jinja2_class", "critical"),
    # Freemarker
    ("${\"freemarker\".getClass()}", "java.lang.String", "freemarker_class", "critical"),
    ("<#assign x=\"freemarker\">${x}", "freemarker", "freemarker_assign", "high"),
    # Twig
    ("{{_self.env.getExtensions()}}", "Twig", "twig_env", "critical"),
    # Velocity
    ("#set($x=7*7)${x}", "49", "velocity", "high"),
    # Smarty
    ("{php}echo 'SSTI';{/php}", "SSTI", "smarty", "critical"),
    # Mako
    ("${7*7}", "49", "mako", "high"),
    # Pug/Jade
    ("#{7*7}", "49", "pug", "high"),
]

# WAF bypass payloads
_BYPASS_PAYLOADS = [
    ("{%25+set+x=7*7+%25}{{x}}", "49", "jinja2_url_encode"),
    ("{{''.__class__}}", "__class__", "jinja2_empty_string"),
    ("{{request|attr('application')}}", "application", "jinja2_attr_filter"),
    ("${{7*7}}", "49", "spring_el"),
    ("*{7*7}", "49", "thymeleaf_selection"),
]


async def check(client, endpoints, ctx) -> list[Finding]:
    findings = []
    target = ctx.get("target_raw", "unknown")

    for ep in endpoints[:15]:
        params = [p for p in ep.parameters if p.location in ("query", "body")]
        if not params:
            continue

        for param in params[:3]:
            bl = await client.baseline_request(ep)
            if bl.status in (0, 404, 405):
                break

            found = False

            # Test each SSTI payload
            for payload, expected, engine, sev in _SSTI_PAYLOADS:
                r = await client.send_payload(ep, param.name, payload, param.location)
                if r.status == 0:
                    continue

                if expected in r.body and expected not in bl.body:
                    fp = stable_fingerprint(target, "api.scanner.ssti", engine, ep.path, param.name)
                    findings.append(Finding(
                        severity=sev, plugin_id="api.scanner.ssti",
                        title=f"SSTI ({engine}): {ep.method} {ep.path} [{param.name}]",
                        description=(
                            f"Server-Side Template Injection detected. Engine: {engine}. "
                            f"Payload '{payload}' produced '{expected}' in the response. "
                            f"An attacker can execute arbitrary code on the server."
                        ),
                        evidence=f"path={ep.path} param={param.name} engine={engine} payload={payload} expected={expected}",
                        affected=target, fingerprint=fp, confidence=0.92, cvss=9.8 if sev == "critical" else 8.6,
                        remediation=(
                            f"[{sev.upper()} — CWE-1336 / OWASP API8:2023]\n\n"
                            f"[ENGINE] {engine}\n\n"
                            f"[FIX]\n"
                            f"1. Never pass user input directly into template rendering\n"
                            f"2. Use sandboxed template environments\n"
                            f"3. Jinja2: env = SandboxedEnvironment()\n"
                            f"4. Use logic-less templates (Mustache, Handlebars) where possible\n"
                            f"5. Validate and sanitize all user input"
                        ),
                        references=["https://portswigger.net/web-security/server-side-template-injection"],
                    ))
                    found = True
                    break

            if found:
                continue

            # WAF bypass
            for payload, expected, desc in _BYPASS_PAYLOADS[:3]:
                r = await client.send_payload(ep, param.name, payload, param.location)
                if r.status > 0 and expected in r.body and expected not in bl.body:
                    fp = stable_fingerprint(target, "api.scanner.ssti", "bypass", ep.path, param.name)
                    findings.append(Finding(
                        severity="critical", plugin_id="api.scanner.ssti",
                        title=f"SSTI (WAF bypass): {ep.method} {ep.path} [{param.name}] — {desc}",
                        description=f"SSTI detected via WAF bypass technique '{desc}'.",
                        evidence=f"path={ep.path} param={param.name} bypass={desc} payload={payload}",
                        affected=target, fingerprint=fp, confidence=0.88, cvss=9.8,
                        remediation="[CRITICAL] SSTI via WAF bypass. Fix the code — WAF is insufficient.",
                        references=["https://portswigger.net/web-security/server-side-template-injection"],
                    ))
                    break

    return findings
