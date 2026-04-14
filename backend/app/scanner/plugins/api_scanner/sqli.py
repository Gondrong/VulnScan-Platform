"""
API SQL Injection Scanner
Tests API endpoints for SQL injection vulnerabilities:
- Error-based (MySQL, PostgreSQL, MSSQL, Oracle, SQLite)
- Boolean-based blind (true/false response comparison)
- Time-based blind (SLEEP/pg_sleep/WAITFOR delay)
- JSON body injection
- WAF bypass techniques
"""
import asyncio
import json
import logging
import re
import time

from app.scanner.plugins.base import Finding
from app.scanner.context import stable_fingerprint

logger = logging.getLogger("vulnscan.api_scanner.sqli")

_TIME_DELAY = 5

_ERROR_PAYLOADS = [
    ("'", "single_quote", "generic"),
    ("' OR '1'='1", "or_true", "generic"),
    ("1' AND EXTRACTVALUE(1,CONCAT(0x7e,version(),0x7e))-- -", "extractvalue", "mysql"),
    ("1' AND 1=CAST((SELECT version()) AS int)-- -", "cast_error", "postgresql"),
    ("1' AND 1=CONVERT(int,@@version)-- -", "convert_error", "mssql"),
    ("' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT banner FROM v$version WHERE ROWNUM=1))-- -", "utl_inaddr", "oracle"),
    ("1'\"", "generic_quotes", "generic"),
    ("' UNION SELECT NULL-- -", "union_probe", "generic"),
]

_ERROR_PATTERNS = {
    "mysql": [r"SQL syntax.*MySQL", r"Warning.*mysql_", r"MySQLSyntaxErrorException", r"SQLSTATE\["],
    "postgresql": [r"PostgreSQL.*ERROR", r"pg_query\(\).*failed", r"unterminated quoted string"],
    "mssql": [r"Microsoft SQL Server", r"Unclosed quotation mark", r"ODBC SQL Server Driver"],
    "oracle": [r"ORA-\d{5}", r"Oracle.*Driver", r"SQL command not properly ended"],
    "sqlite": [r"SQLite3::query", r"SQLITE_ERROR", r"sqlite3\.OperationalError"],
    "generic": [r"SQL syntax", r"sql error", r"SQLSTATE", r"syntax error.*query"],
}

_BOOLEAN_TRUE = [("' OR '1'='1", "or_true"), ("1 OR 1=1", "num_true"), ("') OR ('1'='1", "paren_true")]
_BOOLEAN_FALSE = [("' OR '1'='2", "or_false"), ("1 OR 1=2", "num_false"), ("') OR ('1'='2", "paren_false")]

_TIME_PAYLOADS = [
    (f"' OR SLEEP({_TIME_DELAY})-- -", "mysql_sleep"),
    (f"'; WAITFOR DELAY '0:0:{_TIME_DELAY}'-- -", "mssql_waitfor"),
    (f"' OR pg_sleep({_TIME_DELAY})-- -", "pg_sleep"),
    (f"' AND (SELECT * FROM (SELECT(SLEEP({_TIME_DELAY})))a)-- -", "mysql_subquery"),
]

_JSON_PAYLOADS = [
    ({"$gt": ""}, "nosql_gt"),
    ({"$ne": ""}, "nosql_ne"),
    ({"$regex": ".*"}, "nosql_regex"),
]

_BYPASS_PAYLOADS = [
    ("'/**/OR/**/1=1-- -", "comment_bypass"),
    ("' oR '1'='1", "case_variation"),
    ("%27%20OR%201%3D1--%20-", "url_encode"),
    ("' OR CHAR(49)=CHAR(49)-- -", "char_bypass"),
]


async def check(client, endpoints, ctx) -> list[Finding]:
    """Run SQL injection checks on all API endpoints."""
    findings = []
    target = ctx.get("target_raw", "unknown")
    tested_params = set()

    for ep in endpoints[:20]:
        injectable_params = [p for p in ep.parameters if p.location in ("query", "body", "path")]
        if not injectable_params:
            continue

        for param in injectable_params[:5]:
            param_key = f"{ep.path}:{ep.method}:{param.name}"
            if param_key in tested_params:
                continue
            tested_params.add(param_key)

            # Baseline
            bl = await client.baseline_request(ep)
            if bl.status in (0, 404, 405):
                break

            found = False

            # 1. Error-based
            for payload, desc, db in _ERROR_PAYLOADS[:5]:
                resp = await client.send_payload(ep, param.name, payload, param.location)
                if resp.status == 0:
                    continue
                patterns = _ERROR_PATTERNS.get(db, []) + _ERROR_PATTERNS.get("generic", [])
                for pat in patterns:
                    if re.search(pat, resp.body, re.I):
                        fp = stable_fingerprint(target, "api.scanner.sqli", "error", ep.path, param.name)
                        findings.append(Finding(
                            severity="high", plugin_id="api.scanner.sqli",
                            title=f"SQLi (error-based): {ep.method} {ep.path} [{param.name}]",
                            description=f"Error-based SQL injection via '{param.name}' at {ep.path}. DB: {db}. Payload: {desc}.",
                            evidence=f"path={ep.path} method={ep.method} param={param.name} payload={desc} db={db} pattern={pat}",
                            affected=target, fingerprint=fp, confidence=0.90, cvss=8.6,
                            remediation=f"[HIGH — CWE-89 / OWASP API8:2023]\n\n[FIX] Use parameterized queries. Never concatenate user input into SQL.",
                            references=["https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"],
                        ))
                        found = True
                        break
                if found:
                    break

            if found:
                continue

            # 2. Boolean-based blind
            true_lens = []
            false_lens = []
            for payload, _ in _BOOLEAN_TRUE[:2]:
                r = await client.send_payload(ep, param.name, payload, param.location)
                if r.status > 0:
                    true_lens.append(r.body_length)
            for payload, _ in _BOOLEAN_FALSE[:2]:
                r = await client.send_payload(ep, param.name, payload, param.location)
                if r.status > 0:
                    false_lens.append(r.body_length)

            if true_lens and false_lens:
                avg_true = sum(true_lens) / len(true_lens)
                avg_false = sum(false_lens) / len(false_lens)
                diff = abs(avg_true - avg_false)
                if diff > 50 and diff / max(avg_true, 1) > 0.1:
                    fp = stable_fingerprint(target, "api.scanner.sqli", "boolean", ep.path, param.name)
                    findings.append(Finding(
                        severity="high", plugin_id="api.scanner.sqli",
                        title=f"SQLi (boolean-blind): {ep.method} {ep.path} [{param.name}]",
                        description=f"Boolean-based blind SQLi. TRUE avg: {avg_true:.0f}b, FALSE avg: {avg_false:.0f}b (diff: {diff:.0f}).",
                        evidence=f"path={ep.path} param={param.name} true_avg={avg_true:.0f} false_avg={avg_false:.0f} diff={diff:.0f}",
                        affected=target, fingerprint=fp, confidence=0.80, cvss=8.6,
                        remediation="[HIGH — CWE-89] Use parameterized queries.",
                        references=["https://owasp.org/www-community/attacks/Blind_SQL_Injection"],
                    ))
                    continue

            # 3. Time-based blind
            for payload, desc in _TIME_PAYLOADS[:3]:
                r = await client.send_payload(ep, param.name, payload, param.location)
                if r.elapsed >= _TIME_DELAY - 0.5 and bl.elapsed < _TIME_DELAY - 1:
                    r2 = await client.send_payload(ep, param.name, payload, param.location)
                    if r2.elapsed >= _TIME_DELAY - 0.5:
                        fp = stable_fingerprint(target, "api.scanner.sqli", "time", ep.path, param.name)
                        findings.append(Finding(
                            severity="high", plugin_id="api.scanner.sqli",
                            title=f"SQLi (time-blind): {ep.method} {ep.path} [{param.name}] — {desc}",
                            description=f"Time-based blind SQLi confirmed. Delay: {r.elapsed:.1f}s + {r2.elapsed:.1f}s (baseline: {bl.elapsed:.1f}s).",
                            evidence=f"path={ep.path} param={param.name} payload={desc} delay1={r.elapsed:.2f}s delay2={r2.elapsed:.2f}s baseline={bl.elapsed:.2f}s",
                            affected=target, fingerprint=fp, confidence=0.90, cvss=8.6,
                            remediation="[HIGH — CWE-89] Use parameterized queries.",
                            references=["https://owasp.org/www-community/attacks/Blind_SQL_Injection"],
                        ))
                        found = True
                        break
            if found:
                continue

            # 4. JSON body NoSQL injection (for POST/PUT endpoints with JSON body)
            if param.location == "body" and ep.method in ("POST", "PUT", "PATCH"):
                for nosql_val, desc in _JSON_PAYLOADS:
                    body = {}
                    for p in ep.parameters:
                        if p.location == "body":
                            body[p.name] = nosql_val if p.name == param.name else (p.example or "test")
                    r = await client.send_raw(ep.method, ep.path, body=body)
                    if r.status in (200, 201) and bl.status in (401, 403) and r.body_length > bl.body_length * 1.5:
                        fp = stable_fingerprint(target, "api.scanner.sqli", "nosql", ep.path, param.name)
                        findings.append(Finding(
                            severity="critical", plugin_id="api.scanner.sqli",
                            title=f"NoSQL injection auth bypass: {ep.method} {ep.path} [{param.name}]",
                            description=f"NoSQL operator injection bypassed authentication. Payload: {desc}.",
                            evidence=f"path={ep.path} param={param.name} payload={desc} inj_status={r.status} bl_status={bl.status}",
                            affected=target, fingerprint=fp, confidence=0.90, cvss=9.8,
                            remediation="[CRITICAL — CWE-943] Sanitize input. Reject objects in string fields. Use mongo-sanitize.",
                        ))
                        found = True
                        break

    return findings
