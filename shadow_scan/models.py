"""Core data models shared across the probing, persistence and delta layers."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class ErrorType(StrEnum):
    """Classified failure reasons. Stored verbatim in ``observations.error_type``."""

    DNS_FAILURE = "dns_failure"
    CONNECTION_REFUSED = "connection_refused"
    CONNECTION_TIMEOUT = "connection_timeout"
    CONNECTION_ERROR = "connection_error"          # other transport failures (unreachable network, reset, ...)
    READ_TIMEOUT = "read_timeout"
    TLS_ERROR = "tls_error"
    INVALID_URL = "invalid_url"
    REDIRECT_LOOP = "redirect_loop"
    REDIRECT_LIMIT_EXCEEDED = "redirect_limit_exceeded"
    RESPONSE_TOO_LARGE = "response_too_large"      # soft error: body truncated, response still recorded
    CLIENT_ERROR = "client_error"                  # other aiohttp client/protocol errors
    UNEXPECTED_ERROR = "unexpected_error"          # bug guard: anything not classified above


class ChangeType(StrEnum):
    NEW_ASSET = "new_asset"
    # HTTP behaviour
    AVAILABILITY_CHANGED = "availability_changed"
    STATUS_CHANGED = "status_changed"
    ERROR_CHANGED = "error_changed"
    REDIRECT_CHANGED = "redirect_changed"
    # Presentation
    TITLE_CHANGED = "title_changed"
    SERVER_HEADER_CHANGED = "server_header_changed"
    # Content
    CONTENT_CHANGED_MAJOR = "content_changed_major"
    CONTENT_CHANGED_MINOR = "content_changed_minor"


class RunStatus(StrEnum):
    RUNNING = "running"
    COMPLETED = "completed"
    INTERRUPTED = "interrupted"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class Target:
    """A normalized, de-duplicated monitoring target.

    ``key`` is the long-term asset identity: ``host[:port][/path]`` *without* a
    scheme, so ``example.com`` and ``https://example.com`` are the same asset.
    The user's intent is kept separately: ``scheme`` holds the explicitly
    requested scheme. ``None`` means "auto": HTTPS first, HTTP fallback.
    """

    key: str
    hostname: str
    port: int | None = None
    path: str = ""               # path + optional "?query"; "" means "/"
    scheme: str | None = None    # explicitly requested scheme, if any
    original: str = ""           # the input line this target came from

    @property
    def netloc(self) -> str:
        host = f"[{self.hostname}]" if ":" in self.hostname else self.hostname
        return f"{host}:{self.port}" if self.port is not None else host

    def candidate_urls(self, http_fallback: bool) -> list[str]:
        """URLs to try, in order. Explicit schemes are always respected."""
        suffix = f"{self.netloc}{self.path or '/'}"
        if self.scheme is not None:
            return [f"{self.scheme}://{suffix}"]
        if http_fallback:
            return [f"https://{suffix}", f"http://{suffix}"]
        return [f"https://{suffix}"]


@dataclass(slots=True)
class ProbeResult:
    """Everything observed for one target in one run. Never holds the body itself."""

    target: Target
    url: str                                  # URL actually requested first (after scheme selection)
    checked_at: str
    final_url: str | None = None              # last URL that returned an HTTP response
    scheme: str | None = None                 # scheme of the URL that actually answered
    hostname: str | None = None
    fallback_used: bool = False               # True when HTTPS failed and HTTP answered
    status_code: int | None = None
    content_type: str | None = None
    content_length_header: int | None = None
    downloaded_bytes: int = 0
    body_truncated: bool = False
    body_sha256: str | None = None            # raw SHA-256 of the body bytes
    normalized_sha256: str | None = None      # SHA-256 after noise normalization (see normalization.py)
    similarity_sketch: bytes | None = None    # compact content sketch (see similarity.py); not persisted per observation
    fingerprints: dict[str, str] = field(default_factory=dict)
    title: str | None = None
    server_header: str | None = None
    redirect_location: str | None = None      # last Location seen (followed or not)
    redirect_count: int = 0
    response_time_ms: float | None = None
    error_type: ErrorType | None = None
    error_message: str | None = None

    @property
    def http_reachable(self) -> bool:
        """True when an HTTP server answered with a response, whatever happened afterwards."""
        return self.status_code is not None

    # Phase 1 name, kept for compatibility.
    reachable = http_reachable

    @property
    def observation_complete(self) -> bool:
        """True when ShadowScan collected a complete, trustworthy fingerprint.

        Requires a response, a fully-read body (not truncated), and no error at
        all. Redirect loops and limits count as incomplete because the intended
        resource was never reached.
        """
        return self.status_code is not None and self.error_type is None and self.body_sha256 is not None


@dataclass(frozen=True, slots=True)
class PreviousObservation:
    """The subset of a stored observation needed for change detection."""

    id: int
    checked_at: str
    status_code: int | None
    body_sha256: str | None
    title: str | None
    redirect_location: str | None
    final_url: str | None
    error_type: str | None
    normalized_sha256: str | None = None
    server_header: str | None = None
    observation_complete: bool = False

    @property
    def http_reachable(self) -> bool:
        return self.status_code is not None

    reachable = http_reachable


@dataclass(frozen=True, slots=True)
class AssetHistory:
    """Running per-asset counters, maintained incrementally (never by scanning history)."""

    observations: int = 0
    content_comparisons: int = 0       # times two complete observations were compared
    content_changes: int = 0           # times the normalized content differed

    @property
    def change_ratio(self) -> float | None:
        if self.content_comparisons == 0:
            return None
        return round(self.content_changes / self.content_comparisons, 4)

    def to_dict(self) -> dict[str, Any]:
        return {
            "observations": self.observations,
            "content_comparisons": self.content_comparisons,
            "content_changes": self.content_changes,
            "change_ratio": self.change_ratio,
        }


@dataclass(frozen=True, slots=True)
class Change:
    """A single detected delta.

    ``fields`` holds type-specific, JSON-safe values. ``interesting``,
    ``reason`` and ``review_priority`` are filled in by :mod:`scoring`.
    """

    change_type: ChangeType
    target: str
    fields: dict[str, Any] = field(default_factory=dict)
    interesting: bool = False
    reason: str | None = None
    review_priority: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "type": self.change_type.value,
            **self.fields,
            "interesting": self.interesting,
            "reason": self.reason,
            "review_priority": self.review_priority,
        }

    def describe(self) -> str:
        """Short human-readable summary (without the target) for console output."""
        f = self.fields
        match self.change_type:
            case ChangeType.NEW_ASSET:
                if f.get("reachable"):
                    return f"new asset, HTTP {f.get('status_code')}"
                return f"new asset, unreachable ({f.get('error_type')})"
            case ChangeType.STATUS_CHANGED:
                return f"{f.get('old_status')} -> {f.get('new_status')}"
            case ChangeType.AVAILABILITY_CHANGED:
                if f["new"]["state"] == "reachable":
                    return f"newly reachable (HTTP {f['new']['status_code']})"
                return f"stopped responding ({f['new']['error_type']})"
            case ChangeType.ERROR_CHANGED:
                return f"error {f.get('old_error')} -> {f.get('new_error')}"
            case ChangeType.REDIRECT_CHANGED:
                return f"redirect {f.get('old')} -> {f.get('new')}"
            case ChangeType.TITLE_CHANGED:
                return f"title {f.get('old')!r} -> {f.get('new')!r}"
            case ChangeType.SERVER_HEADER_CHANGED:
                return f"server header {f.get('old')!r} -> {f.get('new')!r}"
            case ChangeType.CONTENT_CHANGED_MAJOR | ChangeType.CONTENT_CHANGED_MINOR:
                similarity = f.get("similarity")
                measured = f"similarity {similarity:.2f}" if similarity is not None else "similarity not measured"
                return f"{f.get('magnitude')} content change ({measured})"
        return self.change_type.value


@dataclass(slots=True)
class RunSummary:
    run_id: int | None
    started_at: str
    finished_at: str
    status: RunStatus
    targets_total: int
    targets_processed: int = 0
    reachable: int = 0
    unreachable: int = 0
    incomplete: int = 0                # reachable but no complete fingerprint
    raw_only_changes: int = 0          # raw hash changed but normalized content did not (suppressed noise)
    duration_seconds: float = 0.0
    changes: list[Change] = field(default_factory=list)
    error_counts: dict[str, int] = field(default_factory=dict)
