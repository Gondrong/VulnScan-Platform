"""
Scan execution context — shared state passed between plugins during a scan run.
"""
import hashlib
import json
from typing import Any


class ScanPolicy:
    """
    Governs scanner behaviour: timeouts, retries, concurrency limits.
    """

    def __init__(
        self,
        timeout_seconds: float = 30.0,
        max_concurrency: int = 10,
        follow_redirects: bool = True,
        verify_tls: bool = False,
    ):
        self.timeout_seconds = timeout_seconds
        self.max_concurrency = max_concurrency
        self.follow_redirects = follow_redirects
        self.verify_tls = verify_tls


class ScanContext:
    """
    Mutable context object shared across all plugins in a single scan.
    Plugins write artifacts keyed by their `provides` IDs, and read from
    artifact keys listed in their `consumes`.
    """

    def __init__(self, policy: ScanPolicy | None = None):
        self.policy: ScanPolicy = policy or ScanPolicy()
        self._artifacts: dict[str, Any] = {}
        self._seen_fingerprints: set[str] = set()

    def set(self, key: str, value: Any) -> None:
        self._artifacts[key] = value

    # FIX: add put() as alias for set() — engine.py uses ctx.put(...)
    def put(self, key: str, value: Any) -> None:
        self._artifacts[key] = value

    def get(self, key: str, default: Any = None) -> Any:
        return self._artifacts.get(key, default)

    def has(self, key: str) -> bool:
        return key in self._artifacts

    # FIX: add dedup() method — engine.py calls ctx.dedup(fingerprint)
    def dedup(self, fingerprint: str) -> bool:
        """
        Returns True if this fingerprint has NOT been seen before (i.e. it's new).
        Returns False if it's a duplicate.
        """
        if fingerprint in self._seen_fingerprints:
            return False
        self._seen_fingerprints.add(fingerprint)
        return True


def stable_fingerprint(*parts: Any) -> str:
    """
    Produce a stable 12-char hex fingerprint from arbitrary input.
    Used to deduplicate findings across scan runs.
    """
    raw = json.dumps(parts, default=str, sort_keys=True)
    return hashlib.sha256(raw.encode()).hexdigest()[:12]
