"""
httpx integration — HTTP probing and technology detection.

Probes discovered subdomains and open ports for live HTTP services,
extracting status codes, titles, tech stack, content-length, and more.
Works best after subfinder (probes discovered subdomains) and nmap
(probes open ports).
"""
import asyncio
import json
import logging
import os
import re
import shutil
import tempfile

from app.scanner.plugins.base import Finding, Plugin, PluginMeta, PluginResult
from app.scanner.context import stable_fingerprint

logger = logging.getLogger("vulnscan.plugin.httpx")

META = PluginMeta(
    plugin_id="ext.httpx",
    name="httpx HTTP Prober",
    category="fingerprint",
    provides=["httpx.probes"],
    depends_on=[],
    soft_depends_on=["ext.subfinder", "ext.nmap", "fingerprint.http"],
    enabled_by_default=True,
    timeout_seconds=120.0,
)

# Technologies that warrant explicit findings
_NOTABLE_TECH = {
    "wordpress": ("low", "WordPress detected", "Keep WordPress, themes, and plugins up to date."),
    "joomla": ("low", "Joomla detected", "Keep Joomla and extensions up to date."),
    "drupal": ("low", "Drupal detected", "Keep Drupal and modules up to date."),
    "phpmyadmin": ("medium", "phpMyAdmin exposed", "Restrict phpMyAdmin access to trusted IPs or VPN."),
    "tomcat": ("low", "Apache Tomcat detected", "Remove default Tomcat pages and manager in production."),
    "jenkins": ("medium", "Jenkins exposed", "Restrict Jenkins access. Enable authentication."),
    "grafana": ("low", "Grafana detected", "Ensure Grafana requires authentication."),
    "kibana": ("medium", "Kibana exposed", "Restrict Kibana access. Enable X-Pack security."),
    "gitlab": ("low", "GitLab instance detected", "Ensure GitLab registration is disabled if not needed."),
    "weblogic": ("medium", "Oracle WebLogic detected", "WebLogic has frequent critical CVEs. Keep patched."),
    "iis": ("info", "Microsoft IIS detected", ""),
    "nginx": ("info", "Nginx detected", ""),
    "apache": ("info", "Apache HTTPD detected", ""),
}


def _is_python_script(path: str) -> bool:
    try:
        with open(path, "rb") as f:
            head = f.read(64)
    except OSError:
        return False
    return head.startswith(b"#!") and b"python" in head


def _resolve_httpx() -> tuple[str | None, str]:
    """Path to ProjectDiscovery httpx, plus a reason when it is unavailable.

    `pip install httpx` (an openai SDK dependency) installs its own `httpx`
    console script at /usr/local/bin/httpx, overwriting the ProjectDiscovery
    binary. That script rejects every flag used here, so the plugin used to
    report "0 live HTTP services" on every scan. The image installs the real
    binary as `httpx-pd` for that reason.
    """
    for name in ("httpx-pd", "httpx"):
        path = shutil.which(name)
        if path and not _is_python_script(path):
            return path, ""
    if shutil.which("httpx"):
        return None, "only the Python httpx CLI is on PATH (not ProjectDiscovery httpx)"
    return None, "httpx is not installed"


class Check(Plugin):
    async def run(self, target: str, ctx) -> PluginResult:
        httpx_bin, missing_reason = _resolve_httpx()
        if not httpx_bin:
            logger.warning("httpx plugin skipped: %s", missing_reason)
            return PluginResult(findings=[Finding(
                plugin_id=META.plugin_id,
                title="httpx not found — skipping HTTP probing",
                severity="info",
                evidence=missing_reason,
                fingerprint=stable_fingerprint(target, META.plugin_id, "missing"),
            )])

        effective_timeout = ctx.get("_effective_timeout", META.timeout_seconds)
        options = ctx.get("profile_options", {})
        httpx_opts = options.get("httpx", {})

        # Build target list: subdomains + open ports
        targets: list[str] = []
        subdomains = ctx.get("recon.subdomains", []) or []
        open_ports = ctx.get("net.open_ports", []) or []
        target_raw = ctx.get("target_raw", target)

        # Add primary target
        if re.match(r"^https?://", target_raw, re.I):
            targets.append(target_raw)
        else:
            targets.append(target)

        # Add subdomains (cap at 50 to keep within budget)
        for sub in subdomains[:50]:
            if sub != target and sub not in targets:
                targets.append(sub)

        # Add non-standard HTTP ports from nmap
        http_like_ports = [p for p in open_ports if p not in (80, 443)]
        for port in http_like_ports[:10]:
            targets.append(f"{target}:{port}")

        # Write targets to temp file
        fd, target_file = tempfile.mkstemp(suffix=".txt", prefix="httpx_")
        try:
            with os.fdopen(fd, "w") as f:
                f.write("\n".join(targets))

            cmd = [
                httpx_bin,
                "-l", target_file,
                "-silent",
                "-json",  # JSON Lines; httpx has no -jsonl flag and exits on it
                "-no-color",
                "-timeout", "10",
                "-retries", "1",
                "-threads", str(httpx_opts.get("threads", 25)),
                "-rate-limit", str(httpx_opts.get("rate", 50)),
                # Probe features
                "-status-code",
                "-title",
                "-tech-detect",
                "-content-length",
                "-web-server",
                "-method",
                "-follow-redirects",
            ]

            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=effective_timeout
                )
            except asyncio.TimeoutError:
                try:
                    proc.kill()
                except Exception:
                    pass
                return PluginResult(findings=[Finding(
                    plugin_id=META.plugin_id,
                    title="httpx timed out",
                    severity="info",
                    evidence=f"timeout={effective_timeout}s targets={len(targets)}",
                    affected=target,
                    fingerprint=stable_fingerprint(target, META.plugin_id, "timeout"),
                )])
            except Exception as e:
                return PluginResult(findings=[Finding(
                    plugin_id=META.plugin_id,
                    title=f"httpx error: {e}",
                    severity="info",
                    evidence=str(e)[:300],
                    affected=target,
                    fingerprint=stable_fingerprint(target, META.plugin_id, "error"),
                )])
        finally:
            try:
                os.unlink(target_file)
            except Exception:
                pass

        # A failed run leaves stdout empty, which would otherwise be reported
        # as "0 live HTTP services" — indistinguishable from a real result.
        if proc.returncode != 0 and not stdout.strip():
            err = stderr.decode("utf-8", errors="replace").strip()
            logger.warning("httpx exited %s: %s", proc.returncode, err[:300])
            return PluginResult(findings=[Finding(
                plugin_id=META.plugin_id,
                title=f"httpx failed (exit {proc.returncode})",
                severity="info",
                evidence=err[:300],
                affected=target,
                fingerprint=stable_fingerprint(target, META.plugin_id, "error"),
            )])

        # Parse JSONL
        findings: list[Finding] = []
        probes: list[dict] = []
        seen_tech: set[str] = set()

        for line in stdout.decode("utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            url = entry.get("url", "")
            status = entry.get("status_code", 0)
            title = entry.get("title", "")
            tech = entry.get("tech") or []
            server = entry.get("webserver", "")
            content_length = entry.get("content_length", 0)
            host = entry.get("host", "")

            probes.append({
                "url": url, "status": status, "title": title,
                "tech": tech, "server": server, "length": content_length,
            })

            # Notable technology findings
            for t in tech:
                t_lower = t.lower()
                for key, (sev, tech_title, remed) in _NOTABLE_TECH.items():
                    if key in t_lower and key not in seen_tech:
                        seen_tech.add(key)
                        if sev != "info":  # skip pure info tech detections
                            findings.append(Finding(
                                plugin_id=META.plugin_id,
                                title=f"[httpx] {tech_title}: {t}",
                                severity=sev,
                                description=f"Detected {t} at {url}",
                                evidence=f"url={url} tech={t} server={server} status={status}",
                                affected=url or target,
                                fingerprint=stable_fingerprint(target, META.plugin_id, "tech", key),
                                remediation=remed,
                                confidence=0.80,
                            ))

            # Flag interesting status codes on subdomains
            if host != target and status in (200, 301, 302):
                # This is a live subdomain
                pass  # captured in probes artifact

        # Summary
        live_count = len(probes)
        findings.insert(0, Finding(
            plugin_id=META.plugin_id,
            title=f"httpx: {live_count} live HTTP services found ({len(targets)} probed)",
            severity="info",
            description=f"Probed {len(targets)} targets, {live_count} responded with HTTP.",
            evidence="\n".join(
                f"  {p['status']:3d}  {p['url']:50s}  {p['title'][:40]}"
                for p in probes[:30]
            ),
            affected=target,
            fingerprint=stable_fingerprint(target, META.plugin_id, "summary"),
        ))

        return PluginResult(
            findings=findings,
            artifacts={"httpx.probes": probes},
        )
