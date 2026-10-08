"""Access-control differential analysis and object-identifier reasoning.

Compares responses an endpoint returns under explicitly configured authorization
contexts (e.g. anonymous / viewer / admin). Authentication material is always
user-provided; ShadowScan never obtains credentials, brute forces, or mutates
data. Comparisons are read-only (GET/HEAD); any state-changing authorization
validation is REVIEW_REQUIRED and becomes a manual package instead.

The analysis is deterministic over :class:`ContextResponse` observations, so it
is fully offline-testable. The orchestrator is responsible for producing those
observations safely (GET only, through the budget/rate layer).
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field

from .findings import make_evidence
from .models import Finding, ValidationState

# A privileged response is one that looks like it returned real data (2xx + body).
_AUTH_FAIL_STATUSES = frozenset({401, 403})
_OBJECT_KEY_RE = re.compile(r'"([A-Za-z_][A-Za-z0-9_]{1,40})"\s*:')


@dataclass(frozen=True, slots=True)
class ContextResponse:
    """One endpoint's response under one named auth context (read-only)."""

    context: str                      # "anonymous" | "viewer" | "user" | "admin" | ...
    status: int | None
    body_sha256: str | None
    size: int
    object_keys: frozenset[str] = frozenset()
    error: str | None = None

    @property
    def privileged(self) -> bool:
        return self.status is not None and 200 <= self.status < 300 and self.size > 0


def observe(context: str, status: int | None, body: bytes | str | None) -> ContextResponse:
    """Build a :class:`ContextResponse` fingerprint. Body is hashed, never stored whole."""
    if body is None:
        return ContextResponse(context, status, None, 0)
    if isinstance(body, str):
        raw = body.encode("utf-8", "replace")
        text = body
    else:
        raw = body
        text = body.decode("utf-8", "replace")
    keys = frozenset(_OBJECT_KEY_RE.findall(text[:20000]))
    return ContextResponse(context, status, hashlib.sha256(raw).hexdigest(), len(raw), keys)


@dataclass(slots=True)
class ContextComparison:
    endpoint: str
    responses: dict[str, ContextResponse] = field(default_factory=dict)


def compare_contexts(host: str, endpoint_path: str, responses: dict[str, ContextResponse]) -> list[Finding]:
    """Compare an endpoint's responses across auth contexts into review findings.

    Signals (never vulnerability claims):
    * anonymous receives the same privileged response as a privileged context;
    * a lower-privilege context receives object keys only a higher one should;
    * a context expected to be denied (401/403) instead got a privileged body.
    """
    findings: list[Finding] = []
    anon = responses.get("anonymous")
    privileged_names = [c for c in ("admin", "user", "owner") if c in responses]

    # 1. Anonymous == privileged body (identical hash) -> strong signal.
    if anon is not None and anon.privileged:
        for name in privileged_names:
            other = responses[name]
            if other.privileged and other.body_sha256 == anon.body_sha256:
                findings.append(Finding(
                    check_id="authz.anon_equals_privileged", asset=host, category="authorization",
                    title=f"Anonymous access returns the same privileged response as '{name}'",
                    confidence=0.8, severity_hint="high", endpoint=endpoint_path, review_priority=90,
                    validation_state=ValidationState.VALIDATED_NON_DESTRUCTIVELY, source="authz_diff",
                    evidence=[make_evidence("diff", "identical response across trust boundary",
                                            data={"contexts": ["anonymous", name], "status": other.status})],
                ))

    # 2. Lower context sees object keys exclusive to a higher context.
    order = ["anonymous", "viewer", "user", "admin"]
    present = [c for c in order if c in responses and responses[c].privileged]
    for i, low in enumerate(present):
        for high in present[i + 1:]:
            low_keys, high_keys = responses[low].object_keys, responses[high].object_keys
            leaked = (high_keys - low_keys)
            # If the lower context already has keys that look admin-only, flag it.
            admin_like = {k for k in low_keys if re.search(r"(secret|token|role|admin|internal|ssn|password)", k, re.I)}
            if admin_like and low in ("anonymous", "viewer"):
                findings.append(Finding(
                    check_id="authz.sensitive_key_exposed", asset=host, category="authorization",
                    title=f"'{low}' context response contains sensitive-looking fields",
                    confidence=0.6, severity_hint="medium", endpoint=endpoint_path, review_priority=70,
                    validation_state=ValidationState.SUSPECTED, source="authz_diff",
                    evidence=[make_evidence("diff", "sensitive fields visible to lower context",
                                            data={"context": low, "fields": sorted(admin_like)[:10]})],
                ))

    # 3. A context that authenticated still got denied everywhere, or a denied context got data.
    if anon is not None and anon.privileged and all(
        responses[c].status in _AUTH_FAIL_STATUSES for c in privileged_names if c in responses
    ) and privileged_names:
        findings.append(Finding(
            check_id="authz.inverted", asset=host, category="authorization",
            title="Anonymous succeeds where authenticated contexts are denied (inverted access)",
            confidence=0.5, severity_hint="medium", endpoint=endpoint_path, review_priority=60,
            validation_state=ValidationState.SUSPECTED, source="authz_diff",
            evidence=[make_evidence("diff", "inverted access pattern", data={})],
        ))
    return findings


# --- object-identifier relationship analysis -------------------------------------------

@dataclass(frozen=True, slots=True)
class ObjectRef:
    endpoint_path: str
    parameter: str
    observed_value: str | None = None     # only values already seen in authorized traffic/fixtures


def object_reference_candidates(host: str, endpoint_path: str, param_names: tuple[str, ...]) -> list[ObjectRef]:
    """Identify likely object-reference parameters on an endpoint (for review-gated testing).

    This only *identifies* references; it never enumerates IDs. Any substitution
    testing is manual/review-gated and uses known values only.
    """
    from .classify import ParamClass, classify_parameter

    refs: list[ObjectRef] = []
    for name in param_names:
        if classify_parameter(name) is ParamClass.OBJECT_IDENTIFIER:
            refs.append(ObjectRef(endpoint_path, name))
    # Path-embedded identifiers like /users/{id}.
    for placeholder in re.findall(r"\{(\w+)\}", endpoint_path):
        refs.append(ObjectRef(endpoint_path, placeholder))
    return refs
