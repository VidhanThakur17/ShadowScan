"""Change-aware incremental execution helpers.

Continuous runs must not redo everything. Each analyzable object (JS file,
OpenAPI doc, endpoint evidence, favicon, AI context) has an evidence
*fingerprint*; when it is unchanged since the last run the expensive work is
skipped. Every scheduled task records *why* it was scheduled, for observability.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class TaskReason(StrEnum):
    NEW = "new"                     # never seen before
    CHANGED = "changed"             # fingerprint differs
    FORCED = "forced"               # caller forced re-analysis
    MISSING_RESULT = "missing_result"   # seen but no prior result stored


def fingerprint(payload: Any) -> str:
    """Stable fingerprint of a JSON-serializable evidence payload."""
    blob = json.dumps(payload, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(blob.encode("utf-8", "replace")).hexdigest()


@dataclass(frozen=True, slots=True)
class Task:
    object_type: str
    object_key: str
    reason: TaskReason
    fingerprint: str


@dataclass(slots=True)
class IncrementalPlanner:
    """Decides which objects need (re)analysis, using the ops fingerprint table."""

    store: Any
    now: str
    force: bool = False
    scheduled: list[Task] = field(default_factory=list)
    skipped: int = 0

    def consider(self, object_type: str, object_key: str, evidence: Any) -> Task | None:
        """Return a Task if the object needs analysis, else None (and count a skip)."""
        fp = fingerprint(evidence)
        prior = self.store.fingerprint(object_type, object_key)
        if self.force:
            reason = TaskReason.FORCED
        elif prior is None:
            reason = TaskReason.NEW
        elif prior != fp:
            reason = TaskReason.CHANGED
        else:
            self.skipped += 1
            return None
        task = Task(object_type, object_key, reason, fp)
        self.scheduled.append(task)
        return task

    def commit(self, task: Task) -> None:
        """Record the new fingerprint once the task's analysis has succeeded."""
        self.store.set_fingerprint(task.object_type, task.object_key, task.fingerprint, self.now)

    @property
    def summary(self) -> dict[str, int]:
        by_reason: dict[str, int] = {}
        for t in self.scheduled:
            by_reason[t.reason.value] = by_reason.get(t.reason.value, 0) + 1
        by_reason["skipped_unchanged"] = self.skipped
        return by_reason
