from dataclasses import dataclass, field
from typing import Any, Dict, Set
import hashlib

@dataclass
class ScanPolicy:
    timeout_seconds: float = 8.0
    max_concurrency: int = 10

@dataclass
class ScanContext:
    policy: ScanPolicy
    artifacts: Dict[str, Any] = field(default_factory=dict)
    seen_fingerprints: Set[str] = field(default_factory=set)

    def put(self, key: str, value: Any):
        self.artifacts[key] = value

    def get(self, key: str, default=None):
        return self.artifacts.get(key, default)

    def dedup(self, fp: str) -> bool:
        if not fp:
            return True
        if fp in self.seen_fingerprints:
            return False
        self.seen_fingerprints.add(fp)
        return True

def stable_fingerprint(*parts: str) -> str:
    raw = "|".join([p or "" for p in parts])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]
