"""
API Code Injection Scanner
Tests for server-side code execution via eval()-like functions:
- Python eval/exec
- PHP eval
- Node.js eval/Function
- Ruby eval
- Time-based detection with confirmation
"""
import asyncio
import logging
import re

from app.scanner.plugins.base import Finding
from app.scanner.context import stable_fingerprint

logger = logging.getLogger("vulnscan.api_scanner.code_injection")

_TIME_DELAY = 5
_MATH_RESULT = "5765761"  # 2401 * 2401

# Math-based detection (checks if server evaluates expressions)
_MATH_PAYLOADS = [
    ("7*7", "49", "generic_math"),
    ("2401*2401", _MATH_RESULT, "large_math"),
]

# Language-specific payloads
_PYTHON_PAYLOADS = [
    (f"__import__('time').sleep({_TIME_DELAY})", "python_sleep", "time"),
    ("__import__('os').popen('echo VULNSCAN_CODE').read()", "python_popen", "inband"),
    ("str(7*7)", "49", "python_str_eval", "math"),
]

_PHP_PAYLOADS = [
    (f"sleep({_TIME_DELAY})", "php_sleep", "time"),
    ("phpinfo()", "PHP Version", "php_phpinfo", "inband"),
    ("7*7", "49", "php_math", "math"),
]

_NODE_PAYLOADS = [
    (f"require('child_process').execSync('sleep {_TIME_DELAY}')", "node_sleep", "time"),
    ("7*7", "49", "node_math", "math"),
    ("process.version", "v", "node_version", "inband"),
]

_RUBY_PAYLOADS = [
    (f"sleep({_TIME_DELAY})", "ruby_sleep", "time"),
    ("7*7", "49", "ruby_math", "math"),
]

# All time-based payloads
_TIME_PAYLOADS = [
    (f"__import__('time').sleep({_TIME_DELAY})", "python_time"),
    (f"sleep({_TIME_DELAY})", "php_ruby_time"),
    (f"require('child_process').execSync('sleep {_TIME_DELAY}')", "node_time"),
    (f"Thread.sleep({_TIME_DELAY * 1000})", "java_time"),
    (f"java.lang.Thread.sleep({_TIME_DELAY * 1000})", "java_thread_time"),
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

            # 1. Math-based detection
            for payload, expected, desc in _MATH_PAYLOADS:
                r = await client.send_payload(ep, param.name, payload, param.location)
                if r.status > 0 and expected in r.body and expected not in bl.body:
                    fp = stable_fingerprint(target, "api.scanner.code_injection", "math", ep.path, param.name)
                    findings.append(Finding(
                        severity="critical", plugin_id="api.scanner.code_injection",
                        title=f"Code injection (eval): {ep.method} {ep.path} [{param.name}]",
                        description=(
                            f"Server-side code injection confirmed. The expression '{payload}' "
                            f"was evaluated and produced '{expected}' in the response."
                        ),
                        evidence=f"path={ep.path} param={param.name} payload={payload} expected={expected} desc={desc}",
                        affected=target, fingerprint=fp, confidence=0.92, cvss=9.8,
                        remediation=(
                            "[CRITICAL — CWE-94 / OWASP API8:2023]\n\n"
                            "[FIX]\n"
                            "1. NEVER use eval(), exec(), or Function() with user input\n"
                            "2. Use safe expression parsers (e.g., ast.literal_eval in Python)\n"
                            "3. Implement strict input validation\n"
                            "4. Use sandboxed execution environments"
                        ),
                        references=["https://owasp.org/www-community/attacks/Code_Injection"],
                    ))
                    found = True
                    break

            if found:
                continue

            # 2. Time-based detection
            for payload, desc in _TIME_PAYLOADS[:4]:
                r = await client.send_payload(ep, param.name, payload, param.location)
                if r.elapsed >= _TIME_DELAY - 0.5 and bl.elapsed < _TIME_DELAY - 1:
                    r2 = await client.send_payload(ep, param.name, payload, param.location)
                    if r2.elapsed >= _TIME_DELAY - 0.5:
                        # Determine language
                        lang = "unknown"
                        if "python" in desc:
                            lang = "Python"
                        elif "php" in desc or "ruby" in desc:
                            lang = "PHP/Ruby"
                        elif "node" in desc:
                            lang = "Node.js"
                        elif "java" in desc:
                            lang = "Java"

                        fp = stable_fingerprint(target, "api.scanner.code_injection", "time", ep.path, param.name)
                        findings.append(Finding(
                            severity="critical", plugin_id="api.scanner.code_injection",
                            title=f"Code injection (time-based, {lang}): {ep.method} {ep.path} [{param.name}]",
                            description=(
                                f"Blind code injection confirmed via time delay. "
                                f"Language: {lang}. Delay: {r.elapsed:.1f}s + {r2.elapsed:.1f}s (baseline: {bl.elapsed:.1f}s)."
                            ),
                            evidence=(
                                f"path={ep.path} param={param.name} lang={lang} desc={desc} "
                                f"delay1={r.elapsed:.2f}s delay2={r2.elapsed:.2f}s baseline={bl.elapsed:.2f}s"
                            ),
                            affected=target, fingerprint=fp, confidence=0.88, cvss=9.8,
                            remediation=(
                                f"[CRITICAL — CWE-94] Blind code injection detected ({lang}).\n\n"
                                f"[FIX] Remove eval()/exec() calls. Use safe alternatives."
                            ),
                            references=["https://owasp.org/www-community/attacks/Code_Injection"],
                        ))
                        found = True
                        break

            if found:
                continue

            # 3. In-band detection (language-specific markers)
            inband_checks = [
                ("VULNSCAN_CODE", _PYTHON_PAYLOADS[1][0], "python_inband"),
                ("PHP Version", _PHP_PAYLOADS[1][0], "php_inband"),
            ]
            for marker, payload, desc in inband_checks:
                r = await client.send_payload(ep, param.name, payload, param.location)
                if r.status > 0 and marker in r.body and marker not in bl.body:
                    fp = stable_fingerprint(target, "api.scanner.code_injection", "inband", ep.path, param.name)
                    findings.append(Finding(
                        severity="critical", plugin_id="api.scanner.code_injection",
                        title=f"Code injection (in-band): {ep.method} {ep.path} [{param.name}]",
                        description=f"Server-side code execution confirmed. Marker '{marker}' found in response.",
                        evidence=f"path={ep.path} param={param.name} marker={marker} desc={desc}",
                        affected=target, fingerprint=fp, confidence=0.95, cvss=9.8,
                        remediation="[CRITICAL — CWE-94] Remove eval()/exec(). Use safe expression parsing.",
                    ))
                    break

    return findings
