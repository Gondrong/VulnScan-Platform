import asyncio
import ipaddress
import json
import re
import urllib.parse

from app.core.config import settings
from app.scanner.context import ScanContext, ScanPolicy, stable_fingerprint
from app.scanner.plugins.base import Finding
from app.scanner.plugins.loader import load_plugins, topo_sort

PLUGINS = load_plugins()
ORDER = topo_sort(PLUGINS)


def _parse_target(raw: str) -> tuple[str, str]:
    """
    Parse target into (host, scheme).
    Returns the actual hostname/IP and the detected scheme.
    Handles:
      - plain IP:   10.0.0.1
      - IP:port:    10.0.0.1:8080
      - hostname:   example.internal.local
      - http URL:   http://example.com:8080/path
      - https URL:  https://example.com/path
    """
    raw = raw.strip()
    scheme = "unknown"

    # If it starts with a scheme, parse as URL
    if re.match(r"^https?://", raw, re.I):
        parsed = urllib.parse.urlparse(raw)
        scheme = parsed.scheme.lower()
        host = parsed.hostname or ""
        return host, scheme

    # Strip trailing path/query if any (e.g. "10.0.0.1/path")
    # but NOT CIDR notation like "10.0.0.0/8" — we handle /path after port
    # Check if after stripping port it looks like IP with path
    # Simple split on first "/"
    parts = raw.split("/", 1)
    base = parts[0]  # host or host:port

    # Remove port if present
    if ":" in base:
        # IPv6 in brackets?
        if base.startswith("["):
            host = base.split("]")[0].lstrip("[")
        else:
            host = base.split(":")[0]
    else:
        host = base

    return host, scheme


def _allowlisted(target: str) -> bool:
    """
    Returns True if the target is allowed to be scanned.
    Checks against ALLOWLIST env var (CIDRs and domain suffixes).
    """
    allow_entries = [
        x.strip() for x in settings.ALLOWLIST.split(",") if x.strip()
    ]

    host, _ = _parse_target(target)
    if not host:
        return False

    # Try to match as IP address first
    try:
        ip = ipaddress.ip_address(host)
        for entry in allow_entries:
            if "/" in entry:
                try:
                    network = ipaddress.ip_network(entry, strict=False)
                    if ip in network:
                        return True
                except ValueError:
                    pass
            else:
                # exact IP match
                try:
                    if ip == ipaddress.ip_address(entry):
                        return True
                except ValueError:
                    pass
        return False
    except ValueError:
        pass

    # Match as domain
    host_lower = host.lower().rstrip(".")
    for entry in allow_entries:
        entry = entry.lower()
        if entry.startswith("."):
            # suffix match: .internal.local matches foo.internal.local
            if host_lower == entry.lstrip(".") or host_lower.endswith(entry):
                return True
        else:
            # exact domain match
            if host_lower == entry:
                return True

    return False


def _enabled(selection_json: str) -> list[str]:
    try:
        sel = json.loads(selection_json or "{}")
    except Exception:
        sel = {}

    if not sel:
        enabled = {
            pid
            for pid, chk in PLUGINS.items()
            if chk.meta.enabled_by_default
        }
    else:
        enabled = {
            pid for pid, v in sel.items() if v and pid in PLUGINS
        }

    # Resolve dependencies
    changed = True
    while changed:
        changed = False
        for pid in list(enabled):
            if pid not in PLUGINS:
                continue
            for dep in PLUGINS[pid].meta.depends_on:
                if dep in PLUGINS and dep not in enabled:
                    enabled.add(dep)
                    changed = True

    return [pid for pid in ORDER if pid in enabled]


async def scan_target(
    target: str, profile: dict, workspace_id: int
) -> list[Finding]:
    """
    Main scan entry point.
    Returns a list of Finding objects (not dicts).
    """
    # Allowlist check
    if not _allowlisted(target):
        return [
            Finding(
                severity="info",
                plugin_id="policy.allowlist",
                title="Target blocked by allowlist policy",
                description=(
                    f"Target '{target}' is not in the configured allowlist. "
                    f"Add it to the ALLOWLIST environment variable to permit scanning."
                ),
                evidence=f"ALLOWLIST={settings.ALLOWLIST}",
                affected=target,
                fingerprint=stable_fingerprint(target, "allowlist"),
            )
        ]

    # Resolve actual host for context
    host, scheme = _parse_target(target)

    policy = ScanPolicy(timeout_seconds=float(settings.SCAN_TIMEOUT_SECONDS))
    ctx = ScanContext(policy=policy)
    ctx.put("workspace_id", workspace_id)
    ctx.put("target_raw", target)
    ctx.put("target_host", host)
    ctx.put("target_scheme", scheme)

    try:
        options = json.loads(profile.get("options_json", "{}") or "{}")
    except Exception:
        options = {}
    ctx.put("profile_options", options)

    findings_out: list[Finding] = []
    enabled = _enabled(profile.get("plugin_selection_json", "{}"))

    for pid in enabled:
        chk = PLUGINS[pid]
        try:
            res = await asyncio.wait_for(
                chk.run(host, ctx),
                timeout=chk.meta.timeout_seconds + 2,
            )
        except asyncio.TimeoutError:
            findings_out.append(
                Finding(
                    severity="info",
                    plugin_id=pid,
                    title=f"Plugin timed out: {chk.meta.name}",
                    evidence=f"timeout={chk.meta.timeout_seconds}s",
                    affected=target,
                    fingerprint=stable_fingerprint(target, pid, "timeout"),
                )
            )
            continue
        except Exception as exc:
            findings_out.append(
                Finding(
                    severity="info",
                    plugin_id=pid,
                    title=f"Plugin error: {chk.meta.name}",
                    evidence=str(exc)[:512],
                    affected=target,
                    fingerprint=stable_fingerprint(target, pid, "error"),
                )
            )
            continue

        # Merge artifacts
        for k, v in (res.artifacts or {}).items():
            ctx.put(k, v)

        for f in res.findings or []:
            if not f.fingerprint:
                f.fingerprint = stable_fingerprint(target, f.plugin_id, f.title)
            if not ctx.dedup(f.fingerprint):
                continue
            findings_out.append(f)

    return findings_out
