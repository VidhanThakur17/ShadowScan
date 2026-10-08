"""Expanded, explainable security correlation.

Combines deterministic findings with recon context into prioritized review
items. Every rule has a stable id and an explainable score; nothing here is a
vulnerability claim. Scores are bounded and combined conservatively (the top
signal sets the floor; corroborating signals add a bounded bonus) so scores do
not inflate past 100.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .models import Finding

WEIGHTS: dict[str, int] = {
    "authz_object_access": 97,          # object-id endpoint + auth-context difference
    "anon_privileged": 95,              # anonymous == privileged response
    "new_api_authz": 91,                # JS-changed + new internal endpoint + id/role param
    "openapi_admin_object": 85,         # admin op + object id param in a new spec
    "takeover_candidate": 68,
    "cors_credentialed": 70,
    "open_redirect": 65,
    "exposure_live": 55,
    "graphql_introspection": 50,
    "missing_headers": 15,
    "generic_finding": 20,
}

_CATEGORY_FLOOR = {
    "authorization": 60, "subdomain_takeover": 68, "cors": 45, "open_redirect": 65,
    "exposure": 50, "graphql": 30, "api_authorization": 55, "security_headers": 15,
    "information_disclosure": 12, "cookie_security": 14, "http_methods": 25,
}


@dataclass(slots=True)
class ReviewItem:
    asset: str
    endpoint: str | None
    title: str
    review_priority: int
    reasons: list[str] = field(default_factory=list)
    finding_ids: list[int] = field(default_factory=list)
    validation_state: str = "observed"
    ai_hypothesis: str | None = None


@dataclass(slots=True)
class AssetSecurityFacts:
    """Per-(asset,endpoint) signals gathered for correlation."""

    asset: str
    endpoint: str | None = None
    findings: list[tuple[int, Finding]] = field(default_factory=list)   # (db_id, finding)
    has_object_id_param: bool = False
    has_access_control_param: bool = False
    authz_context_diff: bool = False
    js_changed_new_internal: bool = False
    new_openapi_admin_object: bool = False
    recon_priority: int = 0


def _rule_scores(facts: AssetSecurityFacts) -> list[tuple[str, int, str]]:
    categories = {f.category for _, f in facts.findings}
    out: list[tuple[str, int, str]] = []
    if facts.authz_context_diff and (facts.has_object_id_param or "authorization" in categories):
        out.append(("authz_object_access", WEIGHTS["authz_object_access"],
                    "object-identifier endpoint shows differing responses across auth contexts"))
    if any(f.check_id == "authz.anon_equals_privileged" for _, f in facts.findings):
        out.append(("anon_privileged", WEIGHTS["anon_privileged"],
                    "anonymous access returns a privileged response"))
    if facts.js_changed_new_internal and (facts.has_object_id_param or facts.has_access_control_param):
        out.append(("new_api_authz", WEIGHTS["new_api_authz"],
                    "changed JS exposed a new internal endpoint with an id/role parameter"))
    if facts.new_openapi_admin_object:
        out.append(("openapi_admin_object", WEIGHTS["openapi_admin_object"],
                    "new API documentation exposes an admin operation with an object identifier"))
    if "subdomain_takeover" in categories:
        out.append(("takeover_candidate", WEIGHTS["takeover_candidate"], "dangling third-party resource (candidate)"))
    if any(f.category == "cors" and "credential" in f.title.lower() for _, f in facts.findings) or \
       any(f.check_id == "active.cors" and "reflected" in f.title.lower() for _, f in facts.findings):
        out.append(("cors_credentialed", WEIGHTS["cors_credentialed"], "credentialed/reflected CORS"))
    if "open_redirect" in categories and any("accepted" in f.title.lower() for _, f in facts.findings):
        out.append(("open_redirect", WEIGHTS["open_redirect"], "external redirect destination accepted"))
    if "exposure" in categories:
        out.append(("exposure_live", WEIGHTS["exposure_live"], "sensitive path exposed"))
    if any(f.check_id == "graphql.introspection" for _, f in facts.findings):
        out.append(("graphql_introspection", WEIGHTS["graphql_introspection"], "GraphQL introspection enabled"))
    return out


def correlate(facts: AssetSecurityFacts) -> ReviewItem | None:
    """Produce a single prioritized review item for an (asset, endpoint), or None."""
    scores = _rule_scores(facts)
    # Floor from the highest-priority individual finding category.
    finding_floor = max((_CATEGORY_FLOOR.get(f.category, WEIGHTS["generic_finding"])
                         for _, f in facts.findings), default=0)
    if not scores and not facts.findings:
        return None
    if scores:
        scores.sort(key=lambda s: s[1], reverse=True)
        top = scores[0][1]
        # Corroboration: each extra distinct rule adds a small bounded bonus.
        bonus = min(len(scores) - 1, 3) * 2
        priority = min(100, max(top, finding_floor) + bonus)
        reasons = [r for _, _, r in scores]
    else:
        priority = finding_floor
        reasons = [f.title for _, f in facts.findings[:3]]
    # Strongest validation state wins.
    order = ["observed", "suspected", "manual_validation_required", "validated_non_destructively"]
    vstate = "observed"
    for _, f in facts.findings:
        if order.index(f.validation_state.value) > order.index(vstate):
            vstate = f.validation_state.value
    title = reasons[0] if reasons else (facts.findings[0][1].title if facts.findings else "review")
    return ReviewItem(
        asset=facts.asset, endpoint=facts.endpoint, title=title, review_priority=priority,
        reasons=reasons, finding_ids=[fid for fid, _ in facts.findings], validation_state=vstate,
    )
