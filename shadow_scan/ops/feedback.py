"""Researcher feedback loop, ignore rules and baselines.

Deterministic, bounded ranking adjustment — no machine learning. Feedback shifts
priority within strict caps; ignore rules and baselines *suppress noise* but never
delete evidence and never hide structural attack-surface changes (new host/
endpoint/port/JS route/API doc). Nothing here can override scope or safety policy.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# How much repeated feedback can move a score, total, in either direction.
MAX_FEEDBACK_DELTA = 25
_NEGATIVE = {"false_positive", "noise", "not_applicable", "duplicate", "dismissed"}
_POSITIVE = {"interesting", "confirmed"}

# Categories representing structural attack surface: never suppressed by ignore/baseline.
STRUCTURAL_CATEGORIES = frozenset({
    "new_attack_surface", "subdomain_takeover", "authorization", "api_authorization",
})
STRUCTURAL_CHECK_PREFIXES = ("exposure.", "openapi.", "graphql.", "authz.")


@dataclass(frozen=True, slots=True)
class RankingContext:
    program: str
    category: str
    endpoint_key: str | None
    check_id: str | None


def feedback_delta(category_counts: dict[str, int], endpoint_counts: dict[str, int]) -> int:
    """Bounded priority delta from accumulated feedback.

    Repeated dismissals/noise lower; repeated interesting/confirmed raise. The
    combined magnitude is clamped to ``MAX_FEEDBACK_DELTA`` so feedback can never
    run away or flip a finding's importance entirely.
    """
    def score(counts: dict[str, int]) -> int:
        neg = sum(counts.get(v, 0) for v in _NEGATIVE)
        pos = sum(counts.get(v, 0) for v in _POSITIVE)
        # Diminishing returns: log-ish via min caps.
        return min(pos, 5) * 3 - min(neg, 8) * 4

    raw = score(category_counts) + score(endpoint_counts)
    return max(-MAX_FEEDBACK_DELTA, min(MAX_FEEDBACK_DELTA, raw))


def adjust_priority(base_priority: int, delta: int) -> int:
    return max(0, min(100, base_priority + delta))


class RankingAdjuster:
    """Applies bounded feedback-based adjustment, reading counts from an OpsStore."""

    def __init__(self, store, program: str) -> None:
        self._store = store
        self._program = program
        self._cache: dict[str, dict[str, int]] = {}

    def _counts(self, kind: str, key: str) -> dict[str, int]:
        ck = f"{kind}:{key}"
        if ck not in self._cache:
            self._cache[ck] = self._store.feedback_counts(self._program, kind, key)
        return self._cache[ck]

    def adjust(self, base_priority: int, ctx: RankingContext) -> tuple[int, int]:
        """Return (adjusted_priority, delta)."""
        cat_counts = self._counts("category", ctx.category)
        ep_counts = self._counts("endpoint", ctx.endpoint_key) if ctx.endpoint_key else {}
        delta = feedback_delta(cat_counts, ep_counts)
        return adjust_priority(base_priority, delta), delta


# --- ignore rules ---------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class IgnoreMatch:
    rule_id: int
    rule_type: str
    pattern: str


class IgnoreMatcher:
    """Matches findings against program ignore rules. Structural findings are exempt."""

    def __init__(self, rules: list) -> None:
        # rules: sqlite rows or dicts with id, rule_type, pattern
        self._rules = []
        for r in rules:
            rid = r["id"] if _has(r, "id") else r.get("id", 0)
            rtype = r["rule_type"] if _has(r, "rule_type") else r.get("rule_type", "")
            pat = r["pattern"] if _has(r, "pattern") else r.get("pattern", "")
            compiled = _safe_glob(pat)
            self._rules.append((rid, rtype, pat, compiled))

    def match(self, *, category: str, check_id: str | None, endpoint: str | None,
              parameter: str | None, technology: str | None = None, title: str | None = None) -> IgnoreMatch | None:
        # Never suppress structural attack-surface signals.
        if category in STRUCTURAL_CATEGORIES or (check_id and check_id.startswith(STRUCTURAL_CHECK_PREFIXES)):
            return None
        for rid, rtype, pat, rx in self._rules:
            target = {
                "content_change": endpoint, "path": endpoint, "parameter": parameter,
                "technology": technology, "title": title,
            }.get(rtype)
            if target and rx.search(target):
                return IgnoreMatch(rid, rtype, pat)
        return None


def _has(obj, key: str) -> bool:
    try:
        obj[key]
        return True
    except (KeyError, IndexError, TypeError):
        return False


def _safe_glob(pattern: str) -> re.Pattern[str]:
    """Translate a simple glob (``*``) to a regex, treating the rest literally."""
    parts = [re.escape(p) for p in pattern.split("*")]
    return re.compile(".*".join(parts))


# --- baselines ------------------------------------------------------------------------

class BaselineMatcher:
    """Suppresses repetitive review noise that matches an explicit baseline.

    A baseline says "this is expected" (e.g. a host that always changes, a 403
    that is normal). Only matching *expectations* are suppressed; anything beyond
    the baseline still surfaces, and structural findings are never baselined away.
    """

    def __init__(self, baselines: list) -> None:
        self._by_key: dict[tuple[str, str], set[str]] = {}
        for b in baselines:
            kind = b["scope_kind"] if _has(b, "scope_kind") else b.get("scope_kind")
            key = b["scope_key"] if _has(b, "scope_key") else b.get("scope_key")
            exp = b["expectation"] if _has(b, "expectation") else b.get("expectation")
            self._by_key.setdefault((kind, key), set()).add(exp)

    def is_expected(self, scope_kind: str, scope_key: str, expectation: str) -> bool:
        return expectation in self._by_key.get((scope_kind, scope_key), set())
