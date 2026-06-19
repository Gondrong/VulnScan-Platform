"""
ffuf integration — fast web fuzzer for directory/file discovery.

Discovers hidden directories, files, and endpoints using wordlist-based
fuzzing with high concurrency. Much faster than the built-in dir_crawl.

Bundled wordlists are in /opt/wordlists/ (installed via Dockerfile).
"""
import asyncio
import json
import logging
import os
import re
import shutil

from app.scanner.plugins.base import Finding, Plugin, PluginMeta, PluginResult
from app.scanner.context import stable_fingerprint

logger = logging.getLogger("vulnscan.plugin.ffuf")

META = PluginMeta(
    plugin_id="ext.ffuf",
    name="ffuf Web Fuzzer",
    category="recon",
    provides=["ffuf.directories", "recon.directories"],
    depends_on=[],
    soft_depends_on=["fingerprint.http", "ext.nmap"],
    enabled_by_default=True,
    timeout_seconds=120.0,
)

# Default wordlist paths (bundled in Docker image)
_WORDLISTS = [
    "/opt/wordlists/common.txt",
    "/opt/wordlists/raft-medium-directories.txt",
]

# Interesting status codes to report
_INTERESTING_CODES = {200, 201, 204, 301, 302, 307, 308, 401, 403, 405, 500}

# Sensitive paths that warrant a finding
_SENSITIVE_PATTERNS = {
    r"\.env": ("high", "Environment file exposed (.env)", "Remove .env from web root or block access via web server config."),
    r"\.git": ("high", "Git repository exposed (.git)", "Block access to .git directory. Remove it from web root."),
    r"\.svn": ("high", "SVN repository exposed (.svn)", "Block access to .svn directory."),
    r"\.htpasswd": ("critical", "htpasswd file exposed", "Move .htpasswd outside web root."),
    r"\.htaccess": ("medium", "htaccess file accessible", "Review .htaccess for sensitive rules."),
    r"wp-config": ("critical", "WordPress config exposed", "Block access to wp-config.php."),
    r"phpinfo": ("medium", "phpinfo() page found", "Remove phpinfo files from production."),
    r"admin": ("low", "Admin panel found", "Restrict admin panel access by IP or VPN."),
    r"backup|\.bak|\.old|\.orig": ("medium", "Backup file found", "Remove backup files from web root."),
    r"database|\.sql|\.db": ("high", "Database file/dump exposed", "Remove database files from web root immediately."),
    r"config\.(php|yml|yaml|json|xml|ini)": ("high", "Configuration file exposed", "Block access to configuration files."),
    r"server-status|server-info": ("medium", "Apache server-status/info exposed", "Restrict access to server-status/info."),
    r"elmah\.axd|trace\.axd": ("medium", "ASP.NET diagnostics exposed", "Disable diagnostics in production."),
    r"actuator|health|metrics": ("low", "Spring Boot Actuator endpoint", "Restrict actuator endpoints to internal access."),
}


def _classify_path(path: str) -> tuple[str, str, str] | None:
    """Check if a discovered path matches sensitive patterns."""
    for pattern, (sev, title, remed) in _SENSITIVE_PATTERNS.items():
        if re.search(pattern, path, re.I):
            return sev, title, remed
    return None


class Check(Plugin):
    async def run(self, target: str, ctx) -> PluginResult:
        if not shutil.which("ffuf"):
            return PluginResult(findings=[Finding(
                plugin_id=META.plugin_id,
                title="ffuf not found — skipping directory fuzzing",
                severity="info",
                evidence="ffuf is not installed",
                fingerprint=stable_fingerprint(target, META.plugin_id, "missing"),
            )])

        # Select wordlist
        wordlist = None
        for wl in _WORDLISTS:
            if os.path.exists(wl):
                wordlist = wl
                break
        if not wordlist:
            return PluginResult(findings=[Finding(
                plugin_id=META.plugin_id,
                title="ffuf: no wordlist available",
                severity="info",
                evidence="No wordlist found in /opt/wordlists/",
                fingerprint=stable_fingerprint(target, META.plugin_id, "no_wordlist"),
            )])

        target_raw = ctx.get("target_raw", target)
        scheme = ctx.get("target_scheme", "")
        effective_timeout = ctx.get("_effective_timeout", META.timeout_seconds)
        options = ctx.get("profile_options", {})
        ffuf_opts = options.get("ffuf", {})

        # Build target URL
        if re.match(r"^https?://", target_raw, re.I):
            base_url = target_raw.rstrip("/")
        elif scheme:
            base_url = f"{scheme}://{target}"
        else:
            base_url = f"https://{target}"

        output_file = f"/tmp/ffuf_{target.replace('.', '_')}.json"

        cmd = [
            "ffuf",
            "-u", f"{base_url}/FUZZ",
            "-w", ffuf_opts.get("wordlist", wordlist),
            "-o", output_file,
            "-of", "json",
            "-mc", ffuf_opts.get("match_codes", "200,201,204,301,302,307,308,401,403,405,500"),
            "-t", str(ffuf_opts.get("threads", 40)),
            "-timeout", "10",
            "-rate", str(ffuf_opts.get("rate", 100)),
            "-s",               # silent mode
            "-noninteractive",
            "-ac",              # auto-calibrate filtering
        ]

        # Size filter (optional)
        filter_size = ffuf_opts.get("filter_size", "")
        if filter_size:
            cmd += ["-fs", str(filter_size)]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=effective_timeout)
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except Exception:
                pass
            return PluginResult(findings=[Finding(
                plugin_id=META.plugin_id,
                title="ffuf scan timed out",
                severity="info",
                evidence=f"timeout={effective_timeout}s",
                affected=target,
                fingerprint=stable_fingerprint(target, META.plugin_id, "timeout"),
            )])
        except Exception as e:
            return PluginResult(findings=[Finding(
                plugin_id=META.plugin_id,
                title=f"ffuf error: {e}",
                severity="info",
                evidence=str(e)[:300],
                affected=target,
                fingerprint=stable_fingerprint(target, META.plugin_id, "error"),
            )])

        # Parse results
        results = []
        try:
            if os.path.exists(output_file):
                with open(output_file) as f:
                    data = json.load(f)
                os.unlink(output_file)
                results = data.get("results", [])
        except Exception:
            pass

        findings: list[Finding] = []
        directories: list[str] = []

        for r in results:
            url = r.get("url", "")
            status = r.get("status", 0)
            length = r.get("length", 0)
            words = r.get("words", 0)
            input_val = r.get("input", {}).get("FUZZ", "")

            if status not in _INTERESTING_CODES:
                continue

            path = f"/{input_val}" if input_val else url
            directories.append(path)

            # Check for sensitive paths
            match = _classify_path(path)
            if match:
                sev, title, remed = match
                findings.append(Finding(
                    plugin_id=META.plugin_id,
                    title=f"[ffuf] {title}: {path}",
                    severity=sev,
                    description=f"Discovered {path} (HTTP {status}, {length} bytes)",
                    evidence=f"url={url} status={status} size={length} words={words}",
                    affected=url or target,
                    fingerprint=stable_fingerprint(target, META.plugin_id, "sensitive", path),
                    remediation=remed,
                    confidence=0.85,
                ))
            elif status in (401, 403):
                findings.append(Finding(
                    plugin_id=META.plugin_id,
                    title=f"[ffuf] Protected path found: {path} (HTTP {status})",
                    severity="info",
                    evidence=f"url={url} status={status} size={length}",
                    affected=url or target,
                    fingerprint=stable_fingerprint(target, META.plugin_id, "protected", path),
                ))
            elif status == 500:
                findings.append(Finding(
                    plugin_id=META.plugin_id,
                    title=f"[ffuf] Server error on: {path} (HTTP 500)",
                    severity="low",
                    evidence=f"url={url} status=500 size={length}",
                    affected=url or target,
                    fingerprint=stable_fingerprint(target, META.plugin_id, "error", path),
                    remediation="Investigate server errors — they may reveal stack traces or internal info.",
                ))

        # Summary
        findings.insert(0, Finding(
            plugin_id=META.plugin_id,
            title=f"ffuf: {len(directories)} paths discovered",
            severity="info",
            evidence=f"target={base_url} wordlist={os.path.basename(wordlist)} results={len(results)} paths={directories[:20]}",
            affected=target,
            fingerprint=stable_fingerprint(target, META.plugin_id, "summary"),
        ))

        # Merge with existing directory list from built-in dir_crawl
        prev_dirs = ctx.get("recon.directories", []) or []
        merged = list(set(prev_dirs + directories))

        return PluginResult(
            findings=findings,
            artifacts={
                "recon.directories": merged,
                "ffuf.directories": directories,
            },
        )
