import importlib
from app.scanner.plugins import (
    port_scan, banner_grabber, http_fingerprint, web_tech, favicon_hash,
    cpe_builder, nvd_match, cisa_kev, ssh_inventory, cve_packages, cms_match, tls_basic
)

ALL = [
    port_scan, banner_grabber, http_fingerprint, web_tech, favicon_hash,
    cpe_builder, nvd_match, cisa_kev, ssh_inventory, cve_packages, cms_match, tls_basic
]

def load_plugins():
    plugins = {}
    for mod in ALL:
        plugins[mod.META.plugin_id] = mod.Check()
        plugins[mod.META.plugin_id].meta = mod.META
    return plugins

def topo_sort(plugins: dict):
    visited=set(); temp=set(); out=[]
    def visit(pid):
        if pid in visited: return
        if pid in temp: raise RuntimeError("dependency cycle")
        temp.add(pid)
        for d in plugins[pid].meta.depends_on:
            if d in plugins:
                visit(d)
        temp.remove(pid)
        visited.add(pid)
        out.append(pid)
    for pid in plugins.keys():
        visit(pid)
    return out
