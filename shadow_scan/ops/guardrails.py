"""Production guardrails: resource limits and disk-space protection.

When a limit is reached a component stops *cleanly* and is marked limited;
partial results are preserved and the run does not crash. Disk protection stops
storing bulky transient evidence when free space falls below a threshold.
"""

from __future__ import annotations

import logging
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class ResourceLimits:
    max_total_requests: int = 50_000
    max_total_bytes: int = 2 * 1024 * 1024 * 1024
    max_urls: int = 200_000
    max_js_files: int = 5_000
    max_ast_bytes: int = 4 * 1024 * 1024
    max_security_checks: int = 20_000
    max_ai_calls: int = 200
    max_runtime_seconds: float = 6 * 3600.0
    min_free_disk_bytes: int = 500 * 1024 * 1024


@dataclass(slots=True)
class GuardrailState:
    limits: ResourceLimits
    started_at: float = field(default_factory=time.monotonic)
    requests: int = 0
    total_bytes: int = 0
    urls: int = 0
    js_files: int = 0
    security_checks: int = 0
    ai_calls: int = 0
    limited: set[str] = field(default_factory=set)

    # Each method returns True if the component may proceed, False if it is now limited.
    def allow_request(self, n: int = 1) -> bool:
        if self.requests >= self.limits.max_total_requests:
            return self._limit("requests")
        self.requests += n
        return True

    def add_bytes(self, n: int) -> bool:
        self.total_bytes += n
        if self.total_bytes >= self.limits.max_total_bytes:
            return self._limit("bytes")
        return True

    def allow_url(self) -> bool:
        if self.urls >= self.limits.max_urls:
            return self._limit("urls")
        self.urls += 1
        return True

    def allow_js(self) -> bool:
        if self.js_files >= self.limits.max_js_files:
            return self._limit("js_files")
        self.js_files += 1
        return True

    def allow_security_check(self) -> bool:
        if self.security_checks >= self.limits.max_security_checks:
            return self._limit("security_checks")
        self.security_checks += 1
        return True

    def allow_ai_call(self) -> bool:
        if self.ai_calls >= self.limits.max_ai_calls:
            return self._limit("ai_calls")
        self.ai_calls += 1
        return True

    def runtime_exceeded(self) -> bool:
        if (time.monotonic() - self.started_at) >= self.limits.max_runtime_seconds:
            return self._limit("runtime") is False
        return False

    def _limit(self, name: str) -> bool:
        if name not in self.limited:
            self.limited.add(name)
            logger.warning("Resource limit reached: %s; component will stop cleanly", name)
        return False

    @property
    def is_limited(self) -> bool:
        return bool(self.limited)


def free_disk_bytes(path: Path | str) -> int:
    try:
        return shutil.disk_usage(str(path)).free
    except OSError:
        return 1 << 62   # unknown => assume plenty rather than blocking


def disk_ok(path: Path | str, limits: ResourceLimits) -> bool:
    """True when free space is above the configured floor."""
    return free_disk_bytes(path) >= limits.min_free_disk_bytes
