"""Security-check framework.

A check declares its identity, category, safety classification, which endpoint
types it supports, the evidence it needs, its per-check request budget, and the
testing policy it requires. It receives a :class:`CheckContext` that is the
*only* way to make an active request — and every such request is gated by the
policy decision, the budget governor and the rate limiter.

Checks return structured :class:`Finding` objects (with :class:`Evidence`),
never prose. A check that wants a state-changing test does not perform it; it
emits a REVIEW_REQUIRED finding so a manual validation package is produced.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Protocol

from ..budget import BudgetExceeded, RequestGovernor
from ..models import (
    CheckRequest,
    EndpointInfo,
    Finding,
    PolicyDecision,
    Safety,
    TestingPolicy,
)

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class FetchRecord:
    """A minimal response captured by an active request (for evidence)."""

    status: int | None
    headers: dict[str, str]
    body_excerpt: str
    final_url: str | None
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.status is not None and self.error is None


class ActiveFetcher(Protocol):
    async def __call__(self, request: CheckRequest) -> FetchRecord: ...


@dataclass(slots=True)
class CheckContext:
    """Everything a check may use. Active requests go only through :meth:`request`."""

    endpoint: EndpointInfo
    decision: PolicyDecision
    governor: RequestGovernor
    fetcher: ActiveFetcher
    stored_headers: dict[str, str] = field(default_factory=dict)   # from recon/monitoring
    stored_body_excerpt: str = ""
    stored_status: int | None = None
    program_mode: TestingPolicy = TestingPolicy.SAFE_ACTIVE
    _requests_made: int = 0

    @property
    def host(self) -> str:
        return self.endpoint.host

    async def request(self, request: CheckRequest, *, check_budget: tuple[str, int] | None = None) -> FetchRecord | None:
        """Make one active request, or return ``None`` if policy/budget forbids it.

        Hard gate: active requests are permitted only when the global program
        mode allows active work AND the endpoint's policy decision is SAFE_ACTIVE.
        """
        if self.program_mode in (TestingPolicy.PASSIVE_ONLY,) or not self.decision.may_active:
            logger.debug("Active request suppressed by policy for %s", request.url)
            return None
        endpoint_key = f"{request.method} {self.endpoint.identity or self.endpoint.url()}"
        try:
            lease = await self.governor.acquire(self.host, endpoint_key, check_budget)
        except BudgetExceeded as exc:
            logger.debug("Request budget refused %s: %s", request.url, exc)
            return None
        async with lease:
            record = await self.fetcher(request)
        self._requests_made += 1
        return record


class SecurityCheck(Protocol):
    check_id: str
    category: str
    safety: Safety
    request_budget: int
    required_policy: TestingPolicy

    def supports(self, endpoint: EndpointInfo) -> bool: ...

    async def run(self, ctx: CheckContext) -> list[Finding]: ...


class BaseCheck:
    """Convenience base with sane defaults; subclasses override as needed."""

    check_id: str = "base"
    category: str = "generic"
    safety: Safety = Safety.PASSIVE
    request_budget: int = 0
    required_policy: TestingPolicy = TestingPolicy.PASSIVE_ONLY

    def supports(self, endpoint: EndpointInfo) -> bool:
        return True

    def budget_key(self, ctx: CheckContext) -> tuple[str, int]:
        return (f"{self.check_id}:{ctx.host}", self.request_budget)

    async def run(self, ctx: CheckContext) -> list[Finding]:  # pragma: no cover - overridden
        raise NotImplementedError
