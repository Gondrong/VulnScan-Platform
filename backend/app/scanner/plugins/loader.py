"""
Plugin loader — discovers all scanner plugins and sorts them by dependency order.
"""
import importlib
import logging
import pkgutil
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.scanner.plugins.base import Plugin

logger = logging.getLogger("vulnscan.loader")

# All built-in plugin modules (relative to app.scanner.plugins)
_BUILTIN_PLUGINS = [
    "port_scan",
    "http_fingerprint",
    "web_tech",
]


def load_plugins(plugin_selection: dict | None = None) -> list["Plugin"]:
    """
    Import all plugin modules and return instantiated Plugin objects.

    Args:
        plugin_selection: Dict of {plugin_id: bool} controlling which plugins
                          are enabled. If None, all enabled_by_default plugins run.

    Returns:
        List of Plugin instances in dependency-resolved order.
    """
    from app.scanner.plugins.base import Plugin, PluginMeta  # noqa: F401

    plugins: list[Plugin] = []

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

        # Check if explicitly enabled/disabled in profile
        if plugin_selection is not None:
            enabled = plugin_selection.get(meta.plugin_id, meta.enabled_by_default)
        else:
            enabled = meta.enabled_by_default

        if not enabled:
            logger.debug("Plugin %s is disabled — skipping", meta.plugin_id)
            continue

        instance = check_cls()
        instance.META = meta
        plugins.append(instance)

    return topo_sort(plugins)


def topo_sort(plugins: list["Plugin"]) -> list["Plugin"]:
    """
    Sort plugins so that each plugin runs after its dependencies.
    Uses Kahn's algorithm (BFS topological sort).
    """
    by_id: dict[str, "Plugin"] = {p.META.plugin_id: p for p in plugins}
    in_degree: dict[str, int] = {pid: 0 for pid in by_id}

    for plugin in plugins:
        for dep in (plugin.META.depends_on or []):
            if dep in in_degree:
                in_degree[plugin.META.plugin_id] += 1

    queue = [pid for pid, deg in in_degree.items() if deg == 0]
    sorted_ids: list[str] = []

    while queue:
        pid = queue.pop(0)
        sorted_ids.append(pid)
        for plugin in plugins:
            if pid in (plugin.META.depends_on or []):
                in_degree[plugin.META.plugin_id] -= 1
                if in_degree[plugin.META.plugin_id] == 0:
                    queue.append(plugin.META.plugin_id)

    # Any plugins not reached (cycles or missing deps) — append at end
    remaining = [pid for pid in by_id if pid not in sorted_ids]
    if remaining:
        logger.warning("Plugin dependency cycle or missing dep for: %s", remaining)
    sorted_ids.extend(remaining)

    return [by_id[pid] for pid in sorted_ids if pid in by_id]
