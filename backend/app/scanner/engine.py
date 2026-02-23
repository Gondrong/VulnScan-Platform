import asyncio, json, ipaddress
from app.core.config import settings
from app.scanner.context import ScanContext, ScanPolicy, stable_fingerprint
from app.scanner.plugins.loader import load_plugins, topo_sort
from app.scanner.plugins.base import Finding

PLUGINS = load_plugins()
ORDER = topo_sort(PLUGINS)

def _allowlisted(target: str) -> bool:
    allow = [x.strip() for x in settings.ALLOWLIST.split(",") if x.strip()]
    # IP / CIDR
    try:
        ip = ipaddress.ip_address(target)
        for a in allow:
            if "/" in a:
                try:
                    if ip in ipaddress.ip_network(a, strict=False):
                        return True
                except: pass
        return False
    except:
        # domain suffix
        t = target.lower()
        for a in allow:
            if a.startswith(".") and t.endswith(a):
                return True
        return False

def _enabled(selection_json: str):
    try:
        sel = json.loads(selection_json or "{}")
    except:
        sel = {}
    if not sel:
        enabled = {pid for pid, chk in PLUGINS.items() if chk.meta.enabled_by_default}
    else:
        enabled = {pid for pid, v in sel.items() if v and pid in PLUGINS}
    # include deps
    changed=True
    while changed:
        changed=False
        for pid in list(enabled):
            for d in PLUGINS[pid].meta.depends_on:
                if d in PLUGINS and d not in enabled:
                    enabled.add(d); changed=True
    return [pid for pid in ORDER if pid in enabled]

async def scan_target(target: str, profile: dict, workspace_id: int):
    if not _allowlisted(target):
        return [{"severity":"info","plugin_id":"policy.allowlist","title":"Target blocked by allowlist","evidence":settings.ALLOWLIST,"fingerprint":stable_fingerprint(target,"allowlist")}]

    policy = ScanPolicy(timeout_seconds=float(settings.SCAN_TIMEOUT_SECONDS))
    ctx = ScanContext(policy=policy)
    ctx.put("workspace_id", workspace_id)

    try:
        options = json.loads(profile.get("options_json","{}") or "{}")
    except:
        options = {}
    ctx.put("profile_options", options)

    findings_out=[]
    enabled = _enabled(profile.get("plugin_selection_json","{}"))

    for pid in enabled:
        chk = PLUGINS[pid]
        res = await chk.run(target, ctx)

        # merge artifacts
        for k,v in (res.artifacts or {}).items():
            ctx.put(k, v)

        for f in (res.findings or []):
            if not f.fingerprint:
                f.fingerprint = stable_fingerprint(target, f.plugin_id, f.title)
            if not ctx.dedup(f.fingerprint):
                continue
            findings_out.append(f)

    return findings_out
