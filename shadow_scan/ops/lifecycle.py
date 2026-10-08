"""Finding lifecycle, timeline and regression detection.

Lifecycle states (history is never overwritten; every transition is a timeline
event)::

    new -> triaged -> investigating -> confirmed -> reported
    confirmed -> resolved
    * -> duplicate | informative | false_positive | archived

Regression: if a finding that was previously ``resolved`` is observed again,
ShadowScan does **not** create an unrelated duplicate. It reopens the original
lineage with a ``finding_regressed`` event, high priority, and a bumped
regression counter.
"""

from __future__ import annotations

from dataclasses import dataclass

LIFECYCLE_STATES = (
    "new", "triaged", "investigating", "confirmed", "reported",
    "duplicate", "informative", "false_positive", "resolved", "archived",
)
# Allowed transitions (plus any state may go to archived). Kept permissive but explicit.
_TRANSITIONS: dict[str, set[str]] = {
    "new": {"triaged", "investigating", "confirmed", "duplicate", "informative", "false_positive", "archived"},
    "triaged": {"investigating", "confirmed", "false_positive", "informative", "duplicate", "archived"},
    "investigating": {"confirmed", "false_positive", "informative", "resolved", "archived"},
    "confirmed": {"reported", "resolved", "false_positive", "archived"},
    "reported": {"resolved", "confirmed", "archived"},
    "resolved": {"investigating", "confirmed", "archived"},        # regression reopens
    "duplicate": {"archived", "new"},
    "informative": {"archived", "investigating"},
    "false_positive": {"archived", "investigating"},
    "archived": {"investigating", "new"},
}
REGRESSION_PRIORITY = 95


def can_transition(src: str, dst: str) -> bool:
    if dst not in LIFECYCLE_STATES:
        return False
    return dst == "archived" or dst in _TRANSITIONS.get(src, set())


@dataclass(frozen=True, slots=True)
class RegressionResult:
    is_regression: bool
    dedup_key: str
    lineage_key: str | None = None


class LifecycleManager:
    """Coordinates finding state transitions and regression detection over an OpsStore."""

    def __init__(self, store, program: str) -> None:
        self._store = store
        self._program = program

    def observe(self, dedup_key: str, now: str) -> RegressionResult:
        """Record that a finding was observed this run; detect regression.

        Returns a regression result when a previously-resolved finding reappears.
        """
        prior = self._store.get_finding_state(dedup_key)
        if prior is None:
            self._store.upsert_finding_state(dedup_key, self._program, now)
            self._store.add_timeline(dedup_key, "observed", "first observation", now)
            return RegressionResult(False, dedup_key)
        self._store.upsert_finding_state(dedup_key, self._program, now)
        if prior["lifecycle"] == "resolved":
            # Regression: reopen the SAME lineage, do not create a duplicate.
            self._store.bump_regressed(dedup_key, now)
            self._store.add_timeline(dedup_key, "finding_regressed",
                                     "previously resolved finding observed again", now)
            return RegressionResult(True, dedup_key, prior["lineage_key"])
        self._store.add_timeline(dedup_key, "observed", None, now)
        return RegressionResult(False, dedup_key, prior["lineage_key"])

    def transition(self, dedup_key: str, dst: str, now: str, detail: str | None = None) -> bool:
        state = self._store.get_finding_state(dedup_key)
        src = state["lifecycle"] if state else "new"
        if not can_transition(src, dst):
            return False
        self._store.set_lifecycle(dedup_key, dst, now)
        self._store.add_timeline(dedup_key, f"status:{dst}", detail or f"{src} -> {dst}", now)
        return True

    def mark_resolved_if_absent(self, present_keys: set[str], now: str) -> list[str]:
        """Mark confirmed/reported findings not seen this run as resolved.

        Used by continuous runs to detect fixes. Only auto-resolves findings that
        were human-confirmed/reported, so unconfirmed noise is not auto-closed.
        """
        resolved: list[str] = []
        rows = self._store.conn.execute(
            "SELECT dedup_key, lifecycle FROM ops_finding_state WHERE program=? AND lifecycle IN ('confirmed','reported')",
            (self._program,)).fetchall()
        for row in rows:
            if row[0] not in present_keys:
                self._store.set_lifecycle(row[0], "resolved", now)
                self._store.add_timeline(row[0], "status:resolved", "not observed this run (likely fixed)", now)
                resolved.append(row[0])
        return resolved
