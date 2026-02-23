from dataclasses import dataclass, field
from typing import Any, Dict, List, Literal

Severity = Literal["info","low","medium","high","critical"]

@dataclass
class PluginMeta:
    plugin_id: str
    name: str
    version: str = "1.0.0"
    category: str = "general"
    default_severity: Severity = "info"
    description: str = ""
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    enabled_by_default: bool = True
    depends_on: List[str] = field(default_factory=list)
    provides: List[str] = field(default_factory=list)
    consumes: List[str] = field(default_factory=list)
    timeout_seconds: float = 8.0
    retries: int = 0
    tags: List[str] = field(default_factory=list)

@dataclass
class Finding:
    severity: Severity
    plugin_id: str
    title: str
    description: str = ""
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    evidence: str = ""
    affected: str = ""
    fingerprint: str = ""
    cvss: float | None = None
    cve: str | None = None
    confidence: float = 1.0
    is_kev: bool = False

@dataclass
class PluginResult:
    findings: List[Finding] = field(default_factory=list)
    artifacts: Dict[str, Any] = field(default_factory=dict)

class Plugin:
    meta: PluginMeta
    async def run(self, target: str, ctx) -> PluginResult:
        return PluginResult()
