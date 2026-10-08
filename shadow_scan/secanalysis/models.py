"""Data models for the security-analysis subsystem."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum, StrEnum
from typing import Any


class TestingPolicy(StrEnum):
    """What ShadowScan may do with an endpoint/operation. Ordered by permissiveness."""

    __test__ = False   # not a pytest test class despite the "Test..." name

    PASSIVE_ONLY = "passive_only"            # use stored evidence only; no new requests
    SAFE_ACTIVE = "safe_active"              # a small number of benign, non-state-changing requests
    REVIEW_REQUIRED = "review_required"      # a human must validate; emit a manual package instead
    DISALLOWED = "disallowed"                # never touch, even passively-active


_POLICY_RANK = {
    TestingPolicy.DISALLOWED: 0,
    TestingPolicy.REVIEW_REQUIRED: 1,
    TestingPolicy.PASSIVE_ONLY: 2,
    TestingPolicy.SAFE_ACTIVE: 3,
}


def most_restrictive(*policies: TestingPolicy) -> TestingPolicy:
    """Return the least permissive of the given policies (safety-first combination)."""
    return min(policies, key=lambda p: _POLICY_RANK[p])


class Safety(StrEnum):
    """A check's own safety classification (what it is capable of doing)."""

    PASSIVE = "passive"                      # reads stored evidence; issues no requests
    SAFE_ACTIVE = "safe_active"              # benign, non-state-changing requests only
    REVIEW_REQUIRED = "review_required"      # produces a manual package, never auto-executes


class EndpointClass(StrEnum):
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    ADMINISTRATIVE = "administrative"
    FILE_HANDLING = "file_handling"
    REDIRECT_NAVIGATION = "redirect_navigation"
    USER_MANAGEMENT = "user_management"
    SEARCH_QUERY = "search_query"
    EXPORT_DOWNLOAD = "export_download"
    IMPORT_UPLOAD = "import_upload"
    DEBUG_INTERNAL = "debug_internal"
    PAYMENT_BILLING = "payment_billing"
    API_DOCUMENTATION = "api_documentation"
    GRAPHQL = "graphql"
    WEBHOOK_CALLBACK = "webhook_callback"
    GENERIC = "generic"


class ParamClass(StrEnum):
    OBJECT_IDENTIFIER = "object_identifier"
    ACCESS_CONTROL = "access_control"
    REDIRECT_SSRF = "redirect_ssrf"
    FILE_PATH = "file_path"
    QUERY_INJECTION = "query_injection"
    AUTHENTICATION = "authentication"
    GENERIC = "generic"


class FindingStatus(StrEnum):
    NEW = "new"
    REVIEWING = "reviewing"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"
    RESOLVED = "resolved"
    DUPLICATE = "duplicate"


class ValidationState(StrEnum):
    OBSERVED = "observed"
    SUSPECTED = "suspected"
    VALIDATED_NON_DESTRUCTIVELY = "validated_non_destructively"
    MANUAL_VALIDATION_REQUIRED = "manual_validation_required"


class StageStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    policy: TestingPolicy
    reason: str
    factors: dict[str, Any] = field(default_factory=dict)

    @property
    def may_active(self) -> bool:
        return self.policy is TestingPolicy.SAFE_ACTIVE

    def to_dict(self) -> dict[str, Any]:
        return {"policy": self.policy.value, "reason": self.reason, "factors": self.factors}


@dataclass(frozen=True, slots=True)
class CheckRequest:
    """One active request a check wishes to make, routed through the budget/rate layer."""

    method: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    note: str = ""


@dataclass(frozen=True, slots=True)
class Evidence:
    """Concise, reproducible evidence for a finding. Never an unbounded body."""

    kind: str                                 # "response" | "header" | "js_source" | "openapi" | "dns" | "diff"
    summary: str
    data: dict[str, Any] = field(default_factory=dict)
    source: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "summary": self.summary, "data": self.data, "source": self.source}


@dataclass(slots=True)
class Finding:
    check_id: str
    asset: str
    category: str
    title: str
    confidence: float = 0.5
    severity_hint: str = "info"               # advisory only; NOT a CVSS/vuln claim
    endpoint: str | None = None
    parameter: str | None = None
    review_priority: int = 0
    status: FindingStatus = FindingStatus.NEW
    validation_state: ValidationState = ValidationState.OBSERVED
    source: str = "shadowscan"
    evidence: list[Evidence] = field(default_factory=list)
    dedup_key: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id, "asset": self.asset, "category": self.category,
            "title": self.title, "confidence": round(self.confidence, 3),
            "severity_hint": self.severity_hint, "endpoint": self.endpoint,
            "parameter": self.parameter, "review_priority": self.review_priority,
            "status": self.status.value, "validation_state": self.validation_state.value,
            "source": self.source, "evidence": [e.to_dict() for e in self.evidence],
        }


@dataclass(frozen=True, slots=True)
class EndpointInfo:
    """Normalized endpoint facts handed to classifiers and checks (from recon inventory)."""

    host: str
    path: str
    method: str = "UNKNOWN"
    method_confidence: str = "unknown"
    param_names: tuple[str, ...] = ()
    source: str = "unknown"
    identity: str = ""
    scheme: str = "https"
    port: int | None = None

    def url(self) -> str:
        netloc = self.host if self.port in (None, 80, 443) else f"{self.host}:{self.port}"
        return f"{self.scheme}://{netloc}{self.path}"
