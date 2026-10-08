"""Testing-policy engine.

Security testing never happens simply because an endpoint exists. Every active
security check must obtain a :class:`PolicyDecision` from :class:`PolicyEngine`
first, and may act only when the decision is ``SAFE_ACTIVE``.

The decision combines, safety-first (the most restrictive wins):

* the HTTP method (state-changing verbs downgrade to REVIEW_REQUIRED),
* path and parameter signals (destructive/sensitive words),
* endpoint source and scope state,
* the program profile (global mode, allow/deny lists, allowed methods),
* the operation type the check declares (read vs write vs auth).

Decisions and their reasons are persisted by the caller.
"""

from __future__ import annotations

import re

from .classify import EndpointClass, classify_endpoint
from .models import EndpointInfo, PolicyDecision, TestingPolicy, most_restrictive

# Read-only methods may be SAFE_ACTIVE; the rest are never auto-invoked.
_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
_STATE_CHANGING = frozenset({"POST", "PUT", "PATCH", "DELETE"})

# Path tokens that always force at least REVIEW_REQUIRED even on GET, because a
# GET to them may still change state or is inherently sensitive to probe.
_DESTRUCTIVE_PATH_RE = re.compile(
    r"(?:^|[/_-])(?:logout|signout|delete|remove|destroy|drop|reset|revoke|disable|deactivate|"
    r"purge|wipe|terminate|cancel|refund|charge|pay|transfer|approve|reject|grant|impersonate|"
    r"shutdown|restart|reboot)(?:$|[/_.-])",
    re.I,
)
_DISALLOWED_PATH_RE = re.compile(r"(?:^|[/_-])(?:logout|signout|logoff)(?:$|[/_.-])", re.I)
_SENSITIVE_ENDPOINT_CLASSES = frozenset({
    EndpointClass.PAYMENT_BILLING, EndpointClass.IMPORT_UPLOAD, EndpointClass.ADMINISTRATIVE,
})
_SENSITIVE_PARAMS = frozenset({
    "password", "passwd", "otp", "token", "secret", "api_key", "apikey", "file", "upload",
})


class PolicyEngine:
    """Decides the testing policy for an endpoint/operation.

    ``global_mode`` caps everything: in PASSIVE_ONLY mode no decision is ever more
    permissive than PASSIVE_ONLY, so active checks cannot run at all.
    """

    def __init__(
        self,
        *,
        global_mode: TestingPolicy = TestingPolicy.SAFE_ACTIVE,
        allowed_methods: frozenset[str] = frozenset({"GET", "HEAD", "OPTIONS"}),
        excluded_path_res: tuple[re.Pattern[str], ...] = (),
        in_scope: bool = True,
    ) -> None:
        self._global_mode = global_mode
        self._allowed_methods = {m.upper() for m in allowed_methods}
        self._excluded_path_res = excluded_path_res
        self._default_in_scope = in_scope

    def decide(
        self,
        endpoint: EndpointInfo,
        *,
        operation: str = "read",         # "read" | "write" | "auth"
        in_scope: bool | None = None,
    ) -> PolicyDecision:
        in_scope = self._default_in_scope if in_scope is None else in_scope
        method = (endpoint.method or "UNKNOWN").upper()
        path = endpoint.path
        factors: dict[str, object] = {"method": method, "operation": operation, "in_scope": in_scope}

        if not in_scope:
            return PolicyDecision(TestingPolicy.DISALLOWED, "endpoint is not in scope", factors)

        for pattern in self._excluded_path_res:
            if pattern.search(path):
                return PolicyDecision(TestingPolicy.DISALLOWED, "path matches a program exclusion", factors)

        if _DISALLOWED_PATH_RE.search(path):
            return PolicyDecision(TestingPolicy.DISALLOWED, "session-terminating endpoint (logout) is never probed", factors)

        decisions = [self._global_mode]

        # Method-driven baseline.
        if method in _STATE_CHANGING or operation == "write":
            decisions.append(TestingPolicy.REVIEW_REQUIRED)
            factors["reason_method"] = "state-changing method/operation"
        elif method == "UNKNOWN":
            # We will not assume a safe method; only passive use is allowed.
            decisions.append(TestingPolicy.PASSIVE_ONLY)
            factors["reason_method"] = "unknown method, not assumed safe"
        elif method in _SAFE_METHODS:
            decisions.append(TestingPolicy.SAFE_ACTIVE)
        else:
            decisions.append(TestingPolicy.REVIEW_REQUIRED)

        if method not in self._allowed_methods and method != "UNKNOWN":
            decisions.append(TestingPolicy.REVIEW_REQUIRED)
            factors["reason_allowed"] = "method not in program allow-list"

        # Destructive-looking path forces review regardless of method.
        if _DESTRUCTIVE_PATH_RE.search(path):
            decisions.append(TestingPolicy.REVIEW_REQUIRED)
            factors["reason_path"] = "destructive-looking path token"

        # Sensitive endpoint classes / params force review.
        classes = classify_endpoint(endpoint)
        if any(c in _SENSITIVE_ENDPOINT_CLASSES for c in classes):
            decisions.append(TestingPolicy.REVIEW_REQUIRED)
            factors["reason_class"] = [c.value for c in classes if c in _SENSITIVE_ENDPOINT_CLASSES]
        if {p.lower() for p in endpoint.param_names} & _SENSITIVE_PARAMS:
            decisions.append(TestingPolicy.REVIEW_REQUIRED)
            factors["reason_param"] = "sensitive parameter present"
        if operation == "auth":
            decisions.append(TestingPolicy.REVIEW_REQUIRED)
            factors["reason_auth"] = "authentication operation"

        policy = most_restrictive(*decisions)
        reason = self._reason(policy, factors)
        return PolicyDecision(policy, reason, factors)

    @staticmethod
    def _reason(policy: TestingPolicy, factors: dict[str, object]) -> str:
        if policy is TestingPolicy.SAFE_ACTIVE:
            return "read-only, in-scope, no sensitive signals"
        hints = [v for k, v in factors.items() if k.startswith("reason_")]
        if policy is TestingPolicy.PASSIVE_ONLY:
            return "limited to stored evidence: " + "; ".join(map(str, hints)) if hints else "passive only"
        if policy is TestingPolicy.REVIEW_REQUIRED:
            return "manual validation required: " + "; ".join(map(str, hints)) if hints else "review required"
        return "disallowed"
