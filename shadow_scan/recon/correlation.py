"""Deterministic recon correlation and noise-aware ranking.

The correlation engine combines the signals gathered for one asset in a run
into explainable :class:`ReconSignal` rows, rather than dumping thousands of raw
findings. Every rule has a stable ``rule_id``, a human reason and a priority.
**None of these are vulnerability claims** — they are review signals.

Noise-aware ranking (section 20): generic content changes on an asset that
changes almost every run (high monitoring ``change_ratio``) are down-ranked.
Structural attack-surface changes — new subdomains, ports, endpoints, JS
routes, API docs — keep their weight even on noisy assets, because those are
not the kind of churn that makes a page "noisy".

All weights live in :data:`WEIGHTS`; all rules live in :data:`RULES`.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from .models import ReconEvent, ReconSignal

WEIGHTS: dict[str, int] = {
    "new_live_host_with_api_doc": 96,
    "revived_host_new_port": 92,
    "js_new_internal_endpoint": 91,
    "new_openapi_many_endpoints": 90,
    "new_web_port": 80,
    "new_admin_subdomain": 78,
    "new_subdomain_live": 70,
    "dangling_cname": 68,
    "new_graphql": 66,
    "js_new_endpoint": 64,
    "new_secret_candidate": 72,
    "sensitive_new_parameter": 60,
    "new_source_map": 58,
    "new_openapi": 60,
    "cname_changed": 45,
    "ip_changed": 35,
    "js_changed": 40,
    "technology_changed": 30,
    "favicon_changed": 28,
    "new_endpoint": 35,
    "content_change_generic": 30,
    "new_subdomain": 40,
}

# Keywords that make a new endpoint/route "internal" and thus higher value.
_INTERNAL_MARKERS = ("admin", "internal", "debug", "export", "config", "secret", "private", "backup", "token")
_ADMIN_TITLE_MARKERS = ("admin", "dashboard", "console", "login", "panel", "internal")


@dataclass(slots=True)
class AssetFacts:
    """Everything one recon run learned about one asset, for correlation."""

    asset: str
    events: set[ReconEvent] = field(default_factory=set)
    http_status: int | None = None
    title: str | None = None
    new_ports: list[int] = field(default_factory=list)
    new_endpoints: list[str] = field(default_factory=list)
    new_js_endpoints: list[str] = field(default_factory=list)
    new_parameters: list[str] = field(default_factory=list)      # sensitive names only
    new_openapi_endpoint_count: int = 0
    new_secret_count: int = 0
    change_ratio: float | None = None
    content_change_magnitude: str | None = None                  # major/minor/trivial/unmeasured
    monitoring_priority: int = 0                                  # priority of a generic content change
    monitoring_transition_priority: int = 0                      # priority of an interesting HTTP transition
    monitoring_transition_reason: str | None = None

    def has(self, *events: ReconEvent) -> bool:
        return all(e in self.events for e in events)

    def any_endpoint_internal(self) -> list[str]:
        candidates = self.new_js_endpoints + self.new_endpoints
        return [e for e in candidates if any(m in e.lower() for m in _INTERNAL_MARKERS)]


Rule = Callable[[AssetFacts], ReconSignal | None]


def _signal(facts: AssetFacts, rule_id: str, reason: str, evidence: dict | None = None) -> ReconSignal:
    return ReconSignal(rule_id, facts.asset, reason, WEIGHTS[rule_id], evidence or {})


def _title_is_adminish(title: str | None) -> bool:
    return bool(title) and any(m in title.lower() for m in _ADMIN_TITLE_MARKERS)


def _is_2xx(status: int | None) -> bool:
    return status is not None and 200 <= status < 300


# --- rules (each returns a signal or None) ---------------------------------------------


def rule_new_live_host_with_api_doc(f: AssetFacts) -> ReconSignal | None:
    if f.has(ReconEvent.NEW_SUBDOMAIN) and _is_2xx(f.http_status) and ReconEvent.NEW_OPENAPI in f.events:
        return _signal(f, "new_live_host_with_api_doc",
                       f"Newly discovered host is live (HTTP {f.http_status}) and exposes API documentation "
                       f"({f.new_openapi_endpoint_count} endpoints)",
                       {"status": f.http_status, "new_endpoints": f.new_openapi_endpoint_count})
    return None


def rule_revived_host_new_port(f: AssetFacts) -> ReconSignal | None:
    if f.has(ReconEvent.DNS_BECAME_LIVE) and f.new_ports and _is_2xx(f.http_status):
        return _signal(f, "revived_host_new_port",
                       f"Previously dead host now resolves, exposes new port(s) {sorted(f.new_ports)} and "
                       f"serves HTTP {f.http_status}",
                       {"ports": sorted(f.new_ports), "status": f.http_status})
    return None


def rule_js_new_internal_endpoint(f: AssetFacts) -> ReconSignal | None:
    internal = [e for e in f.new_js_endpoints if any(m in e.lower() for m in _INTERNAL_MARKERS)]
    if ReconEvent.JS_CHANGED in f.events and internal:
        return _signal(f, "js_new_internal_endpoint",
                       f"Changed JavaScript introduced internal-looking endpoint(s): {', '.join(internal[:3])}",
                       {"endpoints": internal[:10]})
    return None


def rule_new_openapi_many_endpoints(f: AssetFacts) -> ReconSignal | None:
    if ReconEvent.NEW_OPENAPI in f.events and f.new_openapi_endpoint_count >= 20:
        return _signal(f, "new_openapi_many_endpoints",
                       f"New API documentation exposes {f.new_openapi_endpoint_count} previously unseen endpoints",
                       {"new_endpoints": f.new_openapi_endpoint_count})
    return None


def rule_new_secret_candidate(f: AssetFacts) -> ReconSignal | None:
    if f.new_secret_count:
        return _signal(f, "new_secret_candidate",
                       f"{f.new_secret_count} new secret-like value(s) found in JavaScript (candidate, unverified)",
                       {"count": f.new_secret_count})
    return None


def rule_new_web_port(f: AssetFacts) -> ReconSignal | None:
    web_ports = [p for p in f.new_ports if p in (80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9000)]
    if ReconEvent.NEW_OPEN_PORT in f.events and web_ports and not f.has(ReconEvent.DNS_BECAME_LIVE):
        return _signal(f, "new_web_port",
                       f"New web-facing port(s) exposed: {sorted(web_ports)}", {"ports": sorted(web_ports)})
    return None


def rule_new_admin_subdomain(f: AssetFacts) -> ReconSignal | None:
    if f.has(ReconEvent.NEW_SUBDOMAIN) and _is_2xx(f.http_status) and (
        _title_is_adminish(f.title) or any(m in f.asset.lower() for m in ("admin", "internal", "dev", "staging"))
    ):
        return _signal(f, "new_admin_subdomain",
                       f"New subdomain is live (HTTP {f.http_status})" + (f", title: {f.title!r}" if f.title else ""),
                       {"status": f.http_status, "title": f.title})
    return None


def rule_new_subdomain_live(f: AssetFacts) -> ReconSignal | None:
    if f.has(ReconEvent.NEW_SUBDOMAIN) and _is_2xx(f.http_status):
        return _signal(f, "new_subdomain_live", f"New subdomain is live (HTTP {f.http_status})",
                       {"status": f.http_status, "title": f.title})
    return None


def rule_dangling_cname(f: AssetFacts) -> ReconSignal | None:
    if ReconEvent.DANGLING_CNAME in f.events:
        return _signal(f, "dangling_cname",
                       "CNAME points to a target that does not resolve (review for possible takeover; not confirmed)")
    return None


def rule_new_graphql(f: AssetFacts) -> ReconSignal | None:
    if ReconEvent.NEW_GRAPHQL in f.events:
        return _signal(f, "new_graphql", "GraphQL endpoint candidate discovered (introspection not performed)")
    return None


def rule_js_new_endpoint(f: AssetFacts) -> ReconSignal | None:
    if f.new_js_endpoints:
        return _signal(f, "js_new_endpoint",
                       f"JavaScript references new endpoint(s): {', '.join(f.new_js_endpoints[:3])}",
                       {"endpoints": f.new_js_endpoints[:10]})
    return None


def rule_sensitive_new_parameter(f: AssetFacts) -> ReconSignal | None:
    if f.new_parameters:
        unique = list(dict.fromkeys(f.new_parameters))   # same name on many endpoints -> show once
        return _signal(f, "sensitive_new_parameter",
                       f"New sensitive-looking parameter(s): {', '.join(unique[:5])}",
                       {"parameters": unique[:10]})
    return None


def rule_new_source_map(f: AssetFacts) -> ReconSignal | None:
    if ReconEvent.NEW_SOURCE_MAP in f.events:
        return _signal(f, "new_source_map", "New JavaScript source map reference discovered")
    return None


def rule_new_openapi(f: AssetFacts) -> ReconSignal | None:
    if ReconEvent.NEW_OPENAPI in f.events and f.new_openapi_endpoint_count < 20:
        return _signal(f, "new_openapi", "New API documentation discovered",
                       {"new_endpoints": f.new_openapi_endpoint_count})
    return None


def rule_cname_changed(f: AssetFacts) -> ReconSignal | None:
    if ReconEvent.CNAME_CHANGED in f.events:
        return _signal(f, "cname_changed", "CNAME target changed")
    return None


def rule_ip_changed(f: AssetFacts) -> ReconSignal | None:
    if ReconEvent.IP_CHANGED in f.events:
        return _signal(f, "ip_changed", "Resolved IP set changed")
    return None


def rule_technology_changed(f: AssetFacts) -> ReconSignal | None:
    if f.events & {ReconEvent.TECHNOLOGY_ADDED, ReconEvent.VERSION_CHANGED, ReconEvent.TECHNOLOGY_REMOVED}:
        return _signal(f, "technology_changed", "Technology stack changed")
    return None


def rule_favicon_changed(f: AssetFacts) -> ReconSignal | None:
    if ReconEvent.FAVICON_CHANGED in f.events:
        return _signal(f, "favicon_changed", "Favicon changed (possible new/cloned application)")
    return None


def rule_new_endpoint(f: AssetFacts) -> ReconSignal | None:
    if f.new_endpoints and not f.new_js_endpoints:
        return _signal(f, "new_endpoint", f"{len(f.new_endpoints)} new endpoint(s) discovered",
                       {"endpoints": f.new_endpoints[:10]})
    return None


def rule_monitoring_transition(f: AssetFacts) -> ReconSignal | None:
    """Surface an interesting HTTP transition the monitoring engine already flagged
    (e.g. 403/404 -> 200), carrying its priority through to the review queue."""
    if f.monitoring_transition_priority >= 50 and f.monitoring_transition_reason:
        return ReconSignal("monitoring_transition", f.asset,
                           f"Monitoring flagged an HTTP transition: {f.monitoring_transition_reason}",
                           f.monitoring_transition_priority,
                           {"priority": f.monitoring_transition_priority})
    return None


def rule_content_change_generic(f: AssetFacts) -> ReconSignal | None:
    if f.content_change_magnitude in ("major", "minor") and f.monitoring_priority:
        return _signal(f, "content_change_generic",
                       f"Monitored content changed ({f.content_change_magnitude})",
                       {"magnitude": f.content_change_magnitude})
    return None


# Order is not significance; priority comes from WEIGHTS.
RULES: tuple[Rule, ...] = (
    rule_new_live_host_with_api_doc,
    rule_revived_host_new_port,
    rule_js_new_internal_endpoint,
    rule_new_openapi_many_endpoints,
    rule_new_secret_candidate,
    rule_new_web_port,
    rule_new_admin_subdomain,
    rule_new_subdomain_live,
    rule_dangling_cname,
    rule_new_graphql,
    rule_js_new_endpoint,
    rule_sensitive_new_parameter,
    rule_new_source_map,
    rule_new_openapi,
    rule_cname_changed,
    rule_ip_changed,
    rule_technology_changed,
    rule_favicon_changed,
    rule_new_endpoint,
    rule_monitoring_transition,
    rule_content_change_generic,
)

# Rule ids whose value is structural attack surface: never down-ranked for noise.
_STRUCTURAL = frozenset({
    "new_live_host_with_api_doc", "revived_host_new_port", "js_new_internal_endpoint",
    "new_openapi_many_endpoints", "new_web_port", "new_admin_subdomain", "new_subdomain_live",
    "dangling_cname", "new_graphql", "js_new_endpoint", "new_secret_candidate",
    "sensitive_new_parameter", "new_source_map", "new_openapi", "new_endpoint", "new_subdomain",
    "monitoring_transition",
})
NOISE_RATIO_THRESHOLD = 0.6     # asset changes content more often than this => "noisy"
NOISE_PENALTY = 20              # subtracted from generic content-change priority on noisy assets


def correlate(facts: AssetFacts) -> list[ReconSignal]:
    """Run all rules for one asset. Multiple signals may fire."""
    signals = [s for s in (rule(facts) for rule in RULES) if s is not None]
    return sorted(signals, key=lambda s: s.review_priority, reverse=True)


def apply_noise_ranking(facts: AssetFacts, signals: list[ReconSignal]) -> list[ReconSignal]:
    """Down-rank only generic content-change signals on naturally dynamic assets."""
    if facts.change_ratio is None or facts.change_ratio < NOISE_RATIO_THRESHOLD:
        return signals
    adjusted: list[ReconSignal] = []
    for s in signals:
        if s.rule_id in _STRUCTURAL:
            adjusted.append(s)
        else:
            new_priority = max(1, s.review_priority - NOISE_PENALTY)
            reason = f"{s.reason} (down-ranked: asset changes on ~{facts.change_ratio:.0%} of runs)"
            adjusted.append(ReconSignal(s.rule_id, s.asset, reason, new_priority, s.evidence))
    return sorted(adjusted, key=lambda s: s.review_priority, reverse=True)


def review_summary(facts: AssetFacts, signals: list[ReconSignal]) -> tuple[int, str, list[str]]:
    """Collapse an asset's signals into a review-item (priority, reason, signal reasons)."""
    if not signals:
        return 0, "", []
    priority = max(s.review_priority for s in signals)
    reasons = [s.reason for s in signals]
    headline = signals[0].reason
    return priority, headline, reasons
