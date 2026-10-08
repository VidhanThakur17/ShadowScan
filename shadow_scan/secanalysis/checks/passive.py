"""Passive checks: use stored evidence only, issue no new requests."""

from __future__ import annotations

from ..findings import make_evidence
from ..models import (
    EndpointInfo,
    Finding,
    FindingStatus,
    Safety,
    TestingPolicy,
    ValidationState,
)
from .base import BaseCheck, CheckContext

# Security response headers whose absence is worth noting (advisory, not a vuln).
_SECURITY_HEADERS = {
    "strict-transport-security": "HSTS not set",
    "content-security-policy": "no Content-Security-Policy",
    "x-content-type-options": "no X-Content-Type-Options (nosniff)",
    "x-frame-options": "no X-Frame-Options / frame-ancestors",
    "referrer-policy": "no Referrer-Policy",
}
_DISCLOSURE_HEADERS = ("server", "x-powered-by", "x-aspnet-version", "x-generator", "x-runtime")


def _lower(headers: dict[str, str]) -> dict[str, str]:
    return {k.lower(): v for k, v in headers.items()}


class SecurityHeadersCheck(BaseCheck):
    check_id = "passive.security_headers"
    category = "security_headers"
    safety = Safety.PASSIVE

    async def run(self, ctx: CheckContext) -> list[Finding]:
        headers = _lower(ctx.stored_headers)
        if not headers:
            return []
        missing = [msg for h, msg in _SECURITY_HEADERS.items() if h not in headers]
        findings: list[Finding] = []
        if missing:
            findings.append(Finding(
                check_id=self.check_id, asset=ctx.host, category=self.category,
                title=f"Missing security headers ({len(missing)})",
                confidence=0.9, severity_hint="low", endpoint=ctx.endpoint.path,
                review_priority=15 + 3 * len(missing),
                validation_state=ValidationState.OBSERVED, source="passive",
                evidence=[make_evidence("header", "missing security headers", data={"missing": missing})],
            ))
        return findings


class TechDisclosureCheck(BaseCheck):
    check_id = "passive.tech_disclosure"
    category = "information_disclosure"
    safety = Safety.PASSIVE

    async def run(self, ctx: CheckContext) -> list[Finding]:
        headers = _lower(ctx.stored_headers)
        disclosed = {h: headers[h] for h in _DISCLOSURE_HEADERS if h in headers and headers[h]}
        # Only report when a version number is actually present (conservative).
        versioned = {h: v for h, v in disclosed.items() if any(ch.isdigit() for ch in v)}
        if not versioned:
            return []
        return [Finding(
            check_id=self.check_id, asset=ctx.host, category=self.category,
            title="Version/technology disclosure in headers",
            confidence=0.8, severity_hint="info", endpoint=ctx.endpoint.path,
            review_priority=12, validation_state=ValidationState.OBSERVED, source="passive",
            evidence=[make_evidence("header", "version disclosure", data={"headers": versioned})],
        )]


class CookieAttributeCheck(BaseCheck):
    check_id = "passive.cookie_attributes"
    category = "cookie_security"
    safety = Safety.PASSIVE

    async def run(self, ctx: CheckContext) -> list[Finding]:
        headers = _lower(ctx.stored_headers)
        set_cookie = headers.get("set-cookie", "")
        if not set_cookie:
            return []
        lowered = set_cookie.lower()
        weak = []
        if "httponly" not in lowered:
            weak.append("missing HttpOnly")
        if "secure" not in lowered:
            weak.append("missing Secure")
        if "samesite" not in lowered:
            weak.append("missing SameSite")
        if not weak:
            return []
        return [Finding(
            check_id=self.check_id, asset=ctx.host, category=self.category,
            title="Cookie set without hardening attributes",
            confidence=0.7, severity_hint="low", endpoint=ctx.endpoint.path,
            review_priority=14, validation_state=ValidationState.OBSERVED, source="passive",
            # The cookie name/value is redacted by make_evidence header redaction upstream.
            evidence=[make_evidence("header", "weak cookie attributes", data={"issues": weak})],
        )]


class PassiveCorsCheck(BaseCheck):
    check_id = "passive.cors"
    category = "cors"
    safety = Safety.PASSIVE

    async def run(self, ctx: CheckContext) -> list[Finding]:
        headers = _lower(ctx.stored_headers)
        acao = headers.get("access-control-allow-origin")
        if acao is None:
            return []
        acac = headers.get("access-control-allow-credentials", "").lower() == "true"
        behavior = None
        if acao == "*":
            behavior = "static wildcard" + (" with credentials (invalid/suspicious)" if acac else "")
        elif acao.lower() == "null":
            behavior = "null origin allowed"
        if behavior is None:
            return []
        priority = 40 if acac else 20
        return [Finding(
            check_id=self.check_id, asset=ctx.host, category=self.category,
            title=f"CORS policy observed: {behavior}",
            confidence=0.75 if acac else 0.6, severity_hint="low",
            endpoint=ctx.endpoint.path, review_priority=priority,
            validation_state=ValidationState.OBSERVED, source="passive",
            status=FindingStatus.NEW,
            evidence=[make_evidence("header", "CORS headers",
                                    data={"allow_origin": acao, "allow_credentials": acac})],
        )]


PASSIVE_CHECKS = (SecurityHeadersCheck(), TechDisclosureCheck(), CookieAttributeCheck(), PassiveCorsCheck())
