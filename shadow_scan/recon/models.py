"""Data models for the recon subsystem.

These are deliberately plain dataclasses/enums with JSON-safe fields, mirroring
the style of :mod:`shadow_scan.models`. Persistence lives in
:mod:`shadow_scan.recon.recon_db`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class ScopeClass(StrEnum):
    IN_SCOPE = "in_scope"
    OUT_OF_SCOPE = "out_of_scope"
    UNKNOWN = "unknown"


class StageStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class ReviewStatus(StrEnum):
    NEW = "new"
    REVIEWING = "reviewing"
    INTERESTING = "interesting"
    DISMISSED = "dismissed"
    RESOLVED = "resolved"


class MethodConfidence(StrEnum):
    KNOWN = "known"
    INFERRED = "inferred"
    UNKNOWN = "unknown"


class ParamLocation(StrEnum):
    QUERY = "query"
    PATH = "path"
    BODY = "body"
    HEADER = "header"
    COOKIE = "cookie"
    UNKNOWN = "unknown"


class ReconEvent(StrEnum):
    """Recon-level deltas, distinct from the monitoring ``ChangeType``."""

    NEW_SUBDOMAIN = "new_subdomain"
    DNS_BECAME_LIVE = "dns_became_live"
    DNS_BECAME_DEAD = "dns_became_dead"
    CNAME_CHANGED = "cname_changed"
    IP_CHANGED = "ip_changed"
    DANGLING_CNAME = "dangling_cname"          # review signal only, never a takeover claim
    NEW_OPEN_PORT = "new_open_port"
    CLOSED_PORT = "closed_port"
    SERVICE_CHANGED = "service_changed"
    NEW_URL = "new_url"
    NEW_JS_FILE = "new_js_file"
    JS_REMOVED = "js_removed"
    JS_CHANGED = "js_changed"
    NEW_JS_ENDPOINT = "new_js_endpoint"
    NEW_JS_PARAMETER = "new_js_parameter"
    NEW_JS_HOSTNAME = "new_js_hostname"
    NEW_SOURCE_MAP = "new_source_map"
    NEW_SECRET_CANDIDATE = "new_secret_candidate"
    NEW_ENDPOINT = "new_endpoint"
    NEW_PARAMETER = "new_parameter"
    NEW_OPENAPI = "new_openapi"
    NEW_GRAPHQL = "new_graphql"
    TECHNOLOGY_ADDED = "technology_added"
    TECHNOLOGY_REMOVED = "technology_removed"
    VERSION_CHANGED = "version_changed"
    FAVICON_CHANGED = "favicon_changed"


class FindingType(StrEnum):
    ENDPOINT_CANDIDATE = "endpoint_candidate"
    PARAMETER_CANDIDATE = "parameter_candidate"
    HOSTNAME_CANDIDATE = "hostname_candidate"
    SECRET_CANDIDATE = "secret_candidate"
    CONFIG_REFERENCE = "config_reference"
    SOURCE_MAP = "source_map"
    ROUTE_CANDIDATE = "route_candidate"
    GRAPHQL_CANDIDATE = "graphql_candidate"


@dataclass(frozen=True, slots=True)
class DiscoveredHost:
    """A hostname produced by a discovery source."""

    hostname: str
    source: str
    scope_class: ScopeClass = ScopeClass.UNKNOWN


@dataclass(frozen=True, slots=True)
class DnsRecord:
    hostname: str
    status: str                       # "resolves" | "nxdomain" | "error"
    a: tuple[str, ...] = ()
    aaaa: tuple[str, ...] = ()
    cname_chain: tuple[str, ...] = ()
    error: str | None = None

    @property
    def resolves(self) -> bool:
        return self.status == "resolves"

    @property
    def terminal_cname(self) -> str | None:
        return self.cname_chain[-1] if self.cname_chain else None


@dataclass(frozen=True, slots=True)
class Service:
    host: str
    port: int
    protocol: str = "tcp"
    service_guess: str | None = None
    banner: str | None = None
    source: str = "unknown"


@dataclass(frozen=True, slots=True)
class UrlRecord:
    url: str
    host: str
    path: str
    param_names: tuple[str, ...] = ()
    source: str = "unknown"
    status_code: int | None = None
    scope_class: ScopeClass = ScopeClass.UNKNOWN


@dataclass(frozen=True, slots=True)
class JsFinding:
    finding_type: FindingType
    value: str
    confidence: float = 0.5
    evidence: str | None = None       # short surrounding context, never the whole file


@dataclass(frozen=True, slots=True)
class Endpoint:
    host: str
    path: str                         # normalized, with {id}-style placeholders
    method: str = "UNKNOWN"
    method_confidence: MethodConfidence = MethodConfidence.UNKNOWN
    param_names: tuple[str, ...] = ()
    source: str = "unknown"
    confidence: float = 0.5

    @property
    def identity(self) -> tuple[str, str, str]:
        """Clean identity so the same endpoint from HTML/JS/history/OpenAPI merges."""
        return (self.host, self.method.upper(), self.path)


@dataclass(frozen=True, slots=True)
class Parameter:
    name: str
    location: ParamLocation
    endpoint_identity: str | None = None   # "METHOD host/path" or None for global
    source: str = "unknown"
    confidence: float = 0.5


@dataclass(frozen=True, slots=True)
class Technology:
    name: str
    version: str | None = None
    confidence: float = 0.5
    evidence: str | None = None


@dataclass(frozen=True, slots=True)
class ReconSignal:
    """Output of the correlation engine. Not a vulnerability claim."""

    rule_id: str
    asset: str
    reason: str
    review_priority: int
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "asset": self.asset,
            "reason": self.reason,
            "review_priority": self.review_priority,
            "evidence": self.evidence,
        }
