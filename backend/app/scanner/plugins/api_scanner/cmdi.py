"""
API Command Injection Scanner
Tests API endpoints for OS command injection:
- In-band (echo marker in response) — Linux + Windows
- Blind time-based (sleep/ping delay measurement)
- Header injection (User-Agent, X-Forwarded-For)
- WAF bypass techniques
"""
import asyncio
import logging
import re
import time

from app.scanner.plugins.base import Finding
from app.scanner.context import stable_fingerprint

logger = logging.getLogger("vulnscan.api_scanner.cmdi")

_MARKER = "VULNSCAN_API_CMDI_8k2m"
_TIME_DELAY = 5

_INBAND_LINUX = [
    (f"; echo {_MARKER}", "semicolon"), (f"| echo {_MARKER}", "pipe"),
    (f"`echo {_MARKER}`", "backtick"), (f"$(echo {_MARKER})", "subshell"),
    (f"& echo {_MARKER} &", "background"), (f"\necho {_MARKER}\n", "newline"),
]

_INBAND_WINDOWS = [
    (f"& echo {_MARKER}", "win_amp"), (f"| echo {_MARKER}", "win_pipe"),
    (f"&& echo {_MARKER}", "win_and"),
]

_BLIND_TIME = [
    (f"; sleep {_TIME_DELAY}", "sleep"), (f"| sleep {_TIME_DELAY}", "pipe_sleep"),
    (f"`sleep {_TIME_DELAY}`", "backtick_sleep"), (f"; ping -c {_TIME_DELAY} 127.0.0.1", "ping"),
    (f"& ping -n {_TIME_DELAY + 1} 127.0.0.1 &", "win_ping"),
]

_BYPASS = [
    (f";${{IFS}}echo${{IFS}}{_MARKER}", "ifs"), (f";ec''ho {_MARKER}", "empty_quote"),
    (f"%0aecho%20{_MARKER}%0a", "url_newline"), (f";e\\cho {_MARKER}", "backslash"),
]

_HEADER_PAYLOADS = [
    ("User-Agent", f"() {{ :; }}; echo {_MARKER}", "shellshock_ua"),
    ("X-Forwarded-For", f"; echo {_MARKER}", "xff"),
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

            # Dynamic parameter pre-check: verify the parameter
            # influences the response. Used to gate time-based blind
            # detection where a static parameter would produce false
            # positives from network jitter.
            alt = await client.send_payload(ep, param.name, "different_test_value", param.location)
            param_is_dynamic = (
                alt.status != bl.status
                or abs(alt.body_length - bl.body_length) > 20
                or alt.body[:500] != bl.body[:500]
            )

            found = False

            # 1. In-band Linux
            for payload, desc in _INBAND_LINUX[:4]:
                r = await client.send_payload(ep, param.name, payload, param.location)
                if r.status > 0 and _MARKER in r.body:
                    fp = stable_fingerprint(target, "api.scanner.cmdi", "inband", ep.path, param.name)
                    findings.append(Finding(
                        severity="critical", plugin_id="api.scanner.cmdi",
                        title=f"CMDi (in-band Linux): {ep.method} {ep.path} [{param.name}]",
                        description=f"OS command injection confirmed. Technique: {desc}. Marker found in response.",
                        evidence=f"path={ep.path} param={param.name} technique={desc} marker=true",
                        affected=target, fingerprint=fp, confidence=0.95, cvss=9.8,
                        remediation="[CRITICAL — CWE-78 / OWASP API8:2023]\n\n[FIX] Never pass user input to shell. Use subprocess with shell=False.",
                        references=["https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html"],
                    ))
                    found = True
                    break

            if found:
                continue

            # 2. In-band Windows
            for payload, desc in _INBAND_WINDOWS[:2]:
                r = await client.send_payload(ep, param.name, payload, param.location)
                if r.status > 0 and _MARKER in r.body:
                    fp = stable_fingerprint(target, "api.scanner.cmdi", "inband_win", ep.path, param.name)
                    findings.append(Finding(
                        severity="critical", plugin_id="api.scanner.cmdi",
                        title=f"CMDi (in-band Windows): {ep.method} {ep.path} [{param.name}]",
                        description=f"Windows command injection confirmed. Technique: {desc}.",
                        evidence=f"path={ep.path} param={param.name} technique={desc}",
                        affected=target, fingerprint=fp, confidence=0.95, cvss=9.8,
                        remediation="[CRITICAL — CWE-78] Avoid shell execution. Use native APIs.",
                    ))
                    found = True
                    break

            if found:
                continue

            # 3. Blind time-based
            # Skip if parameter is static — timing differences would
            # be network noise, not command execution.
            if param_is_dynamic:
                for payload, desc in _BLIND_TIME[:3]:
                    r = await client.send_payload(ep, param.name, payload, param.location)
                    if r.elapsed >= _TIME_DELAY - 0.5 and bl.elapsed < _TIME_DELAY - 1:
                        r2 = await client.send_payload(ep, param.name, payload, param.location)
                        if r2.elapsed >= _TIME_DELAY - 0.5:
                            fp = stable_fingerprint(target, "api.scanner.cmdi", "blind_time", ep.path, param.name)
                            findings.append(Finding(
                                severity="critical", plugin_id="api.scanner.cmdi",
                                title=f"CMDi (blind time): {ep.method} {ep.path} [{param.name}] — {desc}",
                                description=f"Blind command injection via time delay. {r.elapsed:.1f}s + {r2.elapsed:.1f}s (baseline: {bl.elapsed:.1f}s).",
                                evidence=f"path={ep.path} param={param.name} technique={desc} delay1={r.elapsed:.2f}s delay2={r2.elapsed:.2f}s",
                                affected=target, fingerprint=fp, confidence=0.90, cvss=9.8,
                                remediation="[CRITICAL — CWE-78] Never pass user input to shell commands.",
                            ))
                            found = True
                            break

            if found:
                continue

            # 4. WAF bypass
            for payload, desc in _BYPASS[:3]:
                r = await client.send_payload(ep, param.name, payload, param.location)
                if r.status > 0 and _MARKER in r.body:
                    fp = stable_fingerprint(target, "api.scanner.cmdi", "bypass", ep.path, param.name)
                    findings.append(Finding(
                        severity="critical", plugin_id="api.scanner.cmdi",
                        title=f"CMDi (WAF bypass): {ep.method} {ep.path} [{param.name}] — {desc}",
                        description=f"Command injection via WAF bypass '{desc}'.",
                        evidence=f"path={ep.path} param={param.name} bypass={desc}",
                        affected=target, fingerprint=fp, confidence=0.90, cvss=9.8,
                        remediation="[CRITICAL] Fix code — WAF bypass confirmed. Use native APIs.",
                    ))
                    break

            if any(r for r in findings if ep.path in (r.evidence or "")):
                break

        # 5. Header injection
        for hdr, payload, desc in _HEADER_PAYLOADS:
            r = await client.send_raw(ep.method, ep.path, extra_headers={hdr: payload})
            if r.status > 0 and _MARKER in r.body:
                fp = stable_fingerprint(target, "api.scanner.cmdi", "header", ep.path, hdr)
                findings.append(Finding(
                    severity="critical", plugin_id="api.scanner.cmdi",
                    title=f"CMDi via {hdr} header: {ep.path} [{desc}]",
                    description=f"Command injection via {hdr} header ({desc}).",
                    evidence=f"path={ep.path} header={hdr} technique={desc}",
                    affected=target, fingerprint=fp, confidence=0.95, cvss=9.8,
                    remediation=f"[CRITICAL] Sanitize all header values. Update Bash (Shellshock: CVE-2014-6271).",
                ))
                break

    return findings
