"""
Plugin base classes for the VulnScan scanner framework.
"""
from dataclasses import dataclass, field
from typing import Any

# Re-export from context so plugins only need to import from base
from app.scanner.context import ScanContext, ScanPolicy  # noqa: F401


@dataclass
class PluginMeta:
    plugin_id: str
    name: str
    category: str
    provides: list[str] = field(default_factory=list)
    depends_on: list[str] = field(default_factory=list)
    consumes: list[str] = field(default_factory=list)
    enabled_by_default: bool = True
    timeout_seconds: float = 30.0
    # Soft dependencies: affects execution ORDER (runs after these plugins)
    # but does NOT auto-enable them. Use for cross-chain data consumption
    # where the data is optional (e.g., endpoint_prober consuming package_hits).
    soft_depends_on: list[str] = field(default_factory=list)


@dataclass
class Finding:
    plugin_id: str
    title: str
    severity: str = "info"
    description: str = ""
    remediation: str = ""
    evidence: str = ""
    fingerprint: str = ""
    references: list[str] = field(default_factory=list)
    cvss: float | None = None
    cve: str | None = None
    is_kev: bool = False
    confidence: float = 1.0
    affected: str = ""  # FIX: added missing 'affected' field


# Backwards-compat alias
FindingData = Finding


@dataclass
class PluginResult:
    findings: list[Finding] = field(default_factory=list)
    artifacts: dict[str, Any] = field(default_factory=dict)


class Plugin:
    META: PluginMeta

    async def run(self, target: str, ctx: ScanContext) -> PluginResult:
        raise NotImplementedError
