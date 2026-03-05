"""
Plugin loader — discovers all scanner plugins and sorts them by dependency order.
"""
import importlib
import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.scanner.plugins.base import Plugin

logger = logging.getLogger("vulnscan.loader")

# All built-in plugin modules (relative to app.scanner.plugins)
_BUILTIN_PLUGINS = [
    "port_scan",
    "nmap_portscan",
    "http_fingerprint",
    "banner_grabber",
    "web_tech",
    "favicon_hash",
    "cpe_builder",
    "nvd_match",
    "cms_match",
    "cisa_kev",
    "tls_basic",
    "ssh_inventory",
    "cve_packages",
    "local_security",
    "owasp_scanner",
    "dir_crawl",
    "file_inclusion",
]


def load_plugins(plugin_selection: dict | None = None) -> dict[str, "Plugin"]:
    """
    Import all plugin modules and return a dict of {plugin_id: Plugin instance}.

    Args:
        plugin_selection: Dict of {plugin_id: bool} controlling which plugins
                          are enabled. If None, all plugins are loaded (filtering
                          happens later in engine._enabled()).

    Returns:
        Dict mapping plugin_id -> Plugin instance.
    """
    from app.scanner.plugins.base import Plugin, PluginMeta  # noqa: F401

    plugins: dict[str, "Plugin"] = {}

    for module_name in _BUILTIN_PLUGINS:
        full_name = f"app.scanner.plugins.{module_name}"
        try:
            mod = importlib.import_module(full_name)
        except Exception as e:
            logger.warning("Failed to import plugin %s: %s", full_name, e)
            continue

        # Each plugin module must expose a META and a Check class
        meta = getattr(mod, "META", None)
        check_cls = getattr(mod, "Check", None)

        if meta is None or check_cls is None:
            logger.warning("Plugin %s missing META or Check class — skipping", full_name)
            continue

        instance = check_cls()
        instance.meta = meta  # store as .meta for engine.py access
        instance.META = meta  # backwards compat
        plugins[meta.plugin_id] = instance

    return plugins


def topo_sort(plugins: dict[str, "Plugin"] | list["Plugin"]) -> list[str]:
    """
    Sort plugins so that each plugin runs after its dependencies.
    Uses Kahn's algorithm (BFS topological sort).

    Accepts either a dict {plugin_id: Plugin} or a list of Plugins.
    Returns a list of plugin_id strings in dependency order.
    """
    # Normalize input to dict
    if isinstance(plugins, list):
        by_id: dict[str, "Plugin"] = {}
        for p in plugins:
            meta = getattr(p, "meta", None) or getattr(p, "META", None)
            if meta:
                by_id[meta.plugin_id] = p
    else:
        by_id = dict(plugins)

    in_degree: dict[str, int] = {pid: 0 for pid in by_id}

    for pid, plugin in by_id.items():
        meta = getattr(plugin, "meta", None) or getattr(plugin, "META", None)
        if not meta:
            continue
        for dep in (meta.depends_on or []):
            if dep in in_degree:
                in_degree[pid] += 1

    queue = [pid for pid, deg in in_degree.items() if deg == 0]
    sorted_ids: list[str] = []

    while queue:
        pid = queue.pop(0)
        sorted_ids.append(pid)
        for other_pid, plugin in by_id.items():
            meta = getattr(plugin, "meta", None) or getattr(plugin, "META", None)
            if meta and pid in (meta.depends_on or []):
                in_degree[other_pid] -= 1
                if in_degree[other_pid] == 0:
                    queue.append(other_pid)

    # Any plugins not reached (cycles or missing deps) — append at end
    remaining = [pid for pid in by_id if pid not in sorted_ids]
    if remaining:
        logger.warning("Plugin dependency cycle or missing dep for: %s", remaining)
    sorted_ids.extend(remaining)

    return sorted_ids