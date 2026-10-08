"""Reproducible manual-validation packages for REVIEW_REQUIRED findings.

Instead of automatically performing a risky (e.g. state-changing) test, ShadowScan
emits a package a researcher can run by hand (e.g. in Burp Suite): the endpoint,
relevant parameters, a known request shape, the required auth context, the
supporting evidence, a suggested *non-destructive* manual test, and the signals
to expect. ShadowScan never executes these automatically.
"""

from __future__ import annotations

from typing import Any

from .classify import classify_endpoint, classify_parameter
from .models import EndpointInfo, Finding, ParamClass

_TEST_HINTS = {
    ParamClass.OBJECT_IDENTIFIER:
        "With a low-privilege auth context, request this object id, then an id you own under a "
        "different account. Compare responses (read-only) for object-level authorization (BOLA).",
    ParamClass.ACCESS_CONTROL:
        "Submit the request as a low-privilege user while setting this access-control parameter to a "
        "privileged value. Observe whether privilege is granted (function-level authorization).",
    ParamClass.REDIRECT_SSRF:
        "Set this parameter to a benign external URL you control and observe the redirect/fetch target. "
        "Do not target third parties.",
    ParamClass.FILE_PATH:
        "Probe for path traversal using a benign marker (e.g. a known-safe file) only; do not read secrets.",
    ParamClass.AUTHENTICATION:
        "Review how this credential/token is validated. Do NOT brute force or stuff credentials.",
    ParamClass.QUERY_INJECTION:
        "Review input handling manually; do not send injection payloads automatically.",
}


def build_package(finding: Finding, endpoint: EndpointInfo | None = None,
                  required_auth: str | None = None) -> dict[str, Any]:
    """Assemble a manual-validation package dict for a finding."""
    params = endpoint.param_names if endpoint else ((finding.parameter,) if finding.parameter else ())
    param_classes = {p: classify_parameter(p).value for p in params if p}
    suggested: list[str] = []
    for p in params:
        if not p:
            continue
        hint = _TEST_HINTS.get(classify_parameter(p))
        if hint and hint not in suggested:
            suggested.append(hint)
    if not suggested:
        suggested.append("Manually review this endpoint's behavior with a non-destructive request.")
    classes = [c.value for c in classify_endpoint(endpoint)] if endpoint else []
    return {
        "finding": finding.title,
        "asset": finding.asset,
        "endpoint": finding.endpoint,
        "method": endpoint.method if endpoint else "UNKNOWN",
        "endpoint_classes": classes,
        "parameters": param_classes,
        "required_auth_context": required_auth,
        "request_shape": _request_shape(finding, endpoint),
        "evidence": [e.summary for e in finding.evidence][:8],
        "suggested_manual_tests": suggested,
        "expected_signals": [
            "a difference in status or response structure across auth contexts",
            "access to an object or capability the context should not have",
        ],
        "safety_note": "State-changing validation is intentionally NOT automated. Perform manually, "
                       "only against authorized targets, and never destructively.",
    }


def _request_shape(finding: Finding, endpoint: EndpointInfo | None) -> str:
    method = endpoint.method if endpoint and endpoint.method != "UNKNOWN" else "GET"
    path = finding.endpoint or (endpoint.path if endpoint else "/")
    return f"{method} {path}"
