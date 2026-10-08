"""Bounded SAFE_ACTIVE checks: CORS validation, redirect validation, method analysis.

Each issues only a tiny number of benign, non-state-changing requests, every one
gated by policy + budget + rate limiter via :meth:`CheckContext.request`. None
sends a request body or a state-changing method with real data.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from ..classify import ParamClass, classify_parameter
from ..findings import make_evidence
from ..models import (
    CheckRequest,
    EndpointInfo,
    Finding,
    Safety,
    TestingPolicy,
    ValidationState,
)
from .base import BaseCheck, CheckContext

# A benign, clearly-not-a-real-origin probe value, and a harmless redirect sentinel.
_PROBE_ORIGIN = "https://shadowscan-probe.example.net"
_REDIRECT_SENTINEL = "https://shadowscan-probe.example.net/benign"


class ActiveCorsCheck(BaseCheck):
    check_id = "active.cors"
    category = "cors"
    safety = Safety.SAFE_ACTIVE
    request_budget = 3
    required_policy = TestingPolicy.SAFE_ACTIVE

    async def run(self, ctx: CheckContext) -> list[Finding]:
        url = ctx.endpoint.url()
        record = await ctx.request(
            CheckRequest("GET", url, headers={"Origin": _PROBE_ORIGIN}, note="CORS origin reflection probe"),
            check_budget=self.budget_key(ctx),
        )
        if record is None or not record.ok:
            return []
        headers = {k.lower(): v for k, v in record.headers.items()}
        acao = headers.get("access-control-allow-origin")
        acac = headers.get("access-control-allow-credentials", "").lower() == "true"
        if acao is None:
            return []
        if acao == _PROBE_ORIGIN:
            behavior = "reflected arbitrary origin" + (" with credentials" if acac else "")
            confidence, priority, severity = (0.85, 70, "medium") if acac else (0.7, 45, "low")
        elif acao == "*":
            behavior, confidence, priority, severity = "static wildcard", 0.6, 20, "info"
        elif acao.lower() == "null":
            behavior, confidence, priority, severity = "null origin accepted", 0.7, 40, "low"
        else:
            return []
        return [Finding(
            check_id=self.check_id, asset=ctx.host, category=self.category,
            title=f"CORS behavior: {behavior}",
            confidence=confidence, severity_hint=severity, endpoint=ctx.endpoint.path,
            review_priority=priority,
            validation_state=ValidationState.VALIDATED_NON_DESTRUCTIVELY, source="active",
            evidence=[make_evidence("response", "CORS reflection probe",
                                    data={"sent_origin": _PROBE_ORIGIN, "allow_origin": acao,
                                          "allow_credentials": acac, "status": record.status})],
        )]


class RedirectValidationCheck(BaseCheck):
    check_id = "active.open_redirect"
    category = "open_redirect"
    safety = Safety.SAFE_ACTIVE
    request_budget = 3
    required_policy = TestingPolicy.SAFE_ACTIVE

    def supports(self, endpoint: EndpointInfo) -> bool:
        return any(classify_parameter(p) is ParamClass.REDIRECT_SSRF for p in endpoint.param_names)

    async def run(self, ctx: CheckContext) -> list[Finding]:
        redirect_params = [p for p in ctx.endpoint.param_names
                           if classify_parameter(p) is ParamClass.REDIRECT_SSRF]
        if not redirect_params:
            return []
        param = redirect_params[0]
        base = ctx.endpoint.url()
        sep = "&" if "?" in base else "?"
        # A single benign probe: does an absolute external destination get reflected into Location?
        url = f"{base}{sep}{param}={_REDIRECT_SENTINEL}"
        record = await ctx.request(
            CheckRequest("GET", url, note="open-redirect benign destination probe"),
            check_budget=self.budget_key(ctx),
        )
        if record is None or not record.ok:
            return []
        location = {k.lower(): v for k, v in record.headers.items()}.get("location", "")
        accepted = _REDIRECT_SENTINEL in location or urlsplit(location).netloc == urlsplit(_REDIRECT_SENTINEL).netloc
        if record.status in (301, 302, 303, 307, 308) and accepted:
            return [Finding(
                check_id=self.check_id, asset=ctx.host, category=self.category,
                title=f"External redirect destination accepted via '{param}'",
                confidence=0.8, severity_hint="medium", endpoint=ctx.endpoint.path, parameter=param,
                review_priority=65,
                validation_state=ValidationState.VALIDATED_NON_DESTRUCTIVELY, source="active",
                evidence=[make_evidence("response", "redirect reflection",
                                        data={"param": param, "status": record.status,
                                              "location": location})],
            )]
        # Rejected / relative-only is a benign observation, recorded at low priority.
        return [Finding(
            check_id=self.check_id, asset=ctx.host, category=self.category,
            title=f"Redirect parameter '{param}' did not accept external destination",
            confidence=0.5, severity_hint="info", endpoint=ctx.endpoint.path, parameter=param,
            review_priority=5, validation_state=ValidationState.VALIDATED_NON_DESTRUCTIVELY, source="active",
            evidence=[make_evidence("response", "redirect rejected",
                                    data={"param": param, "status": record.status, "location": location})],
        )]


class MethodAnalysisCheck(BaseCheck):
    check_id = "active.methods"
    category = "http_methods"
    safety = Safety.SAFE_ACTIVE
    request_budget = 1
    required_policy = TestingPolicy.SAFE_ACTIVE

    async def run(self, ctx: CheckContext) -> list[Finding]:
        # OPTIONS only: never enumerate verbs by sending them.
        record = await ctx.request(
            CheckRequest("OPTIONS", ctx.endpoint.url(), note="declared-methods via OPTIONS"),
            check_budget=self.budget_key(ctx),
        )
        if record is None or not record.ok:
            return []
        allow = {k.lower(): v for k, v in record.headers.items()}.get("allow", "")
        if not allow:
            return []
        methods = {m.strip().upper() for m in allow.split(",") if m.strip()}
        state_changing = methods & {"PUT", "DELETE", "PATCH"}
        if not state_changing:
            return []
        return [Finding(
            check_id=self.check_id, asset=ctx.host, category=self.category,
            title=f"State-changing methods advertised via OPTIONS: {', '.join(sorted(state_changing))}",
            confidence=0.6, severity_hint="info", endpoint=ctx.endpoint.path,
            review_priority=25,
            validation_state=ValidationState.VALIDATED_NON_DESTRUCTIVELY, source="active",
            evidence=[make_evidence("response", "OPTIONS Allow header",
                                    data={"allow": allow, "state_changing": sorted(state_changing)})],
        )]


ACTIVE_CHECKS = (ActiveCorsCheck(), RedirectValidationCheck(), MethodAnalysisCheck())
