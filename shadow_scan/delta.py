"""Change detection between observations, and the deltas.json report.

Two reference points are used per asset:

* ``previous``: the immediately preceding observation, whatever its quality.
  It is used for HTTP behaviour: availability, status, error, redirect and
  Server header.
* ``baseline``: the most recent *complete* observation. It is used for content
  and title, so a truncated body or a read error never counts as a content
  change, and the comparison resumes against the last trustworthy fingerprint.

Duplicate-event policy (one primary event per facet):

* A brand-new asset produces only ``new_asset``.
* A reachability flip produces only ``availability_changed``. Status, error
  and content differences are implied, so they are not reported separately.
* Both sides unreachable produces ``error_changed`` if the failure mode differs.
* A status-code change produces ``status_changed``. Title, Server header,
  redirect and content-similarity differences are attached to it as
  ``context`` instead of being emitted as separate events.
* Otherwise, each of redirect, Server header, title and content can produce
  its own event.
"""

from __future__ import annotations

import json
import os
import tempfile
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from yarl import URL

from .models import AssetHistory, Change, ChangeType, PreviousObservation, ProbeResult, RunSummary
from .scoring import assess
from .similarity import sketch_similarity

_TYPE_ORDER = {change_type: index for index, change_type in enumerate(ChangeType)}


@dataclass(frozen=True, slots=True)
class ContentComparison:
    """Result of comparing the current body with the asset's content baseline."""

    comparable: bool = False            # both sides are complete observations
    baseline_id: int | None = None
    raw_changed: bool = False
    content_changed: bool = False       # normalized hash differs (raw hash if normalization unavailable)
    similarity: float | None = None     # 1.0 when unchanged; None when not measurable

    @property
    def raw_only(self) -> bool:
        """Raw bytes changed but the normalized content did not: noise that was suppressed."""
        return self.comparable and self.raw_changed and not self.content_changed


def compare_content(
    current: ProbeResult,
    baseline: PreviousObservation | None,
    load_baseline_sketch: Callable[[], bytes | None],
) -> ContentComparison:
    """Compare content fingerprints. The baseline sketch is loaded only if the content changed."""
    if baseline is None or not current.observation_complete:
        return ContentComparison()
    raw_changed = baseline.body_sha256 != current.body_sha256
    if baseline.normalized_sha256 and current.normalized_sha256:
        changed = baseline.normalized_sha256 != current.normalized_sha256
    else:
        # A normalized hash is missing on one side (oversize text). Never compare a
        # normalized hash with a raw one; fall back to raw on both sides.
        changed = raw_changed
    similarity: float | None = 1.0 if not changed else None
    if changed and current.similarity_sketch is not None:
        previous_sketch = load_baseline_sketch()
        if previous_sketch is not None:
            similarity = sketch_similarity(previous_sketch, current.similarity_sketch)
    return ContentComparison(True, baseline.id, raw_changed, changed, similarity)


def content_magnitude(similarity: float | None, trivial_threshold: float, major_threshold: float) -> str:
    if similarity is None:
        return "unmeasured"
    if similarity >= trivial_threshold:
        return "trivial"
    if similarity >= major_threshold:
        return "minor"
    return "major"


def _state(reachable: bool, status_code: int | None, error_type: str | None, title: str | None = None) -> dict[str, Any]:
    state: dict[str, Any] = {
        "state": "reachable" if reachable else "unreachable",
        "status_code": status_code,
        "error_type": error_type,
    }
    if reachable:
        state["title"] = title
    return state


def _host(url: str | None) -> str | None:
    if not url:
        return None
    try:
        return URL(url).host
    except ValueError:
        return None


def detect_changes(
    current: ProbeResult,
    previous: PreviousObservation | None,
    baseline: PreviousObservation | None = None,
    comparison: ContentComparison | None = None,
    history: AssetHistory | None = None,
    *,
    trivial_threshold: float = 0.98,
    major_threshold: float = 0.80,
) -> list[Change]:
    """Return the scored changes between the stored state and ``current``."""
    comparison = comparison or ContentComparison()
    changes = _raw_changes(current, previous, baseline, comparison, history, trivial_threshold, major_threshold)
    return [assess(change) for change in changes]


def _raw_changes(
    current: ProbeResult,
    previous: PreviousObservation | None,
    baseline: PreviousObservation | None,
    comparison: ContentComparison,
    history: AssetHistory | None,
    trivial_threshold: float,
    major_threshold: float,
) -> list[Change]:
    target = current.target.key
    current_error = current.error_type.value if current.error_type else None

    if previous is None:
        return [Change(ChangeType.NEW_ASSET, target, {
            "reachable": current.http_reachable,
            "observation_complete": current.observation_complete,
            "status_code": current.status_code,
            "scheme": current.scheme,
            "final_url": current.final_url,
            "title": current.title,
            "error_type": current_error,
        })]

    if previous.http_reachable != current.http_reachable:
        return [Change(ChangeType.AVAILABILITY_CHANGED, target, {
            "old": _state(previous.http_reachable, previous.status_code, previous.error_type, previous.title),
            "new": _state(current.http_reachable, current.status_code, current_error, current.title),
            "previous_checked_at": previous.checked_at,
        })]

    if not current.http_reachable:
        if previous.error_type != current_error:
            return [Change(ChangeType.ERROR_CHANGED, target, {
                "old_error": previous.error_type,
                "new_error": current_error,
                "previous_checked_at": previous.checked_at,
            })]
        return []

    content_context: dict[str, Any] = {}
    if comparison.content_changed:
        content_context = {
            "similarity": comparison.similarity,
            "magnitude": content_magnitude(comparison.similarity, trivial_threshold, major_threshold),
        }

    if previous.status_code != current.status_code:
        context: dict[str, Any] = {}
        if previous.title != current.title:
            context["title"] = {"old": previous.title, "new": current.title}
        if previous.server_header != current.server_header:
            context["server_header"] = {"old": previous.server_header, "new": current.server_header}
        if previous.redirect_location != current.redirect_location:
            context["redirect"] = {"old": previous.redirect_location, "new": current.redirect_location}
        if content_context:
            context["content"] = content_context
        fields: dict[str, Any] = {"old_status": previous.status_code, "new_status": current.status_code}
        if context:
            fields["context"] = context
        return [Change(ChangeType.STATUS_CHANGED, target, fields)]

    changes: list[Change] = []
    redirect_changed = previous.redirect_location != current.redirect_location
    if redirect_changed:
        changes.append(Change(ChangeType.REDIRECT_CHANGED, target, {
            "old": previous.redirect_location,
            "new": current.redirect_location,
            "host_changed": (
                previous.redirect_location is not None and current.redirect_location is not None
                and _host(previous.redirect_location) != _host(current.redirect_location)
            ),
        }))
    if previous.server_header != current.server_header:
        changes.append(Change(ChangeType.SERVER_HEADER_CHANGED, target, {
            "old": previous.server_header, "new": current.server_header,
        }))
    if redirect_changed and current.status_code is not None and 300 <= current.status_code < 400:
        # A redirect's body usually just echoes its Location, so a body or title change
        # here is the same fact as redirect_changed, not a separate event.
        return changes
    if comparison.comparable and baseline is not None and baseline.title != current.title:
        changes.append(Change(ChangeType.TITLE_CHANGED, target, {"old": baseline.title, "new": current.title}))
    if comparison.content_changed and baseline is not None:
        magnitude = content_context["magnitude"]
        change_type = ChangeType.CONTENT_CHANGED_MAJOR if magnitude in ("major", "unmeasured") else ChangeType.CONTENT_CHANGED_MINOR
        fields = {
            **content_context,
            "old_normalized_hash": baseline.normalized_sha256,
            "new_normalized_hash": current.normalized_sha256,
            "old_raw_hash": baseline.body_sha256,
            "new_raw_hash": current.body_sha256,
            "baseline_checked_at": baseline.checked_at,
        }
        if history is not None:
            fields["history"] = history.to_dict()
        changes.append(Change(change_type, target, fields))
    return changes


def _sort_key(change: Change) -> tuple[int, str, int]:
    return (-change.review_priority, change.target, _TYPE_ORDER[change.change_type])


def sort_changes(changes: list[Change]) -> list[Change]:
    """Highest review priority first; ties broken deterministically by target then type."""
    return sorted(changes, key=_sort_key)


def build_report(summary: RunSummary) -> dict[str, Any]:
    """Build the deltas.json document for the current run only."""
    changes = sort_changes(summary.changes)
    by_type = Counter(c.change_type.value for c in changes)
    return {
        "run_id": summary.run_id,
        "run_timestamp": summary.started_at,
        "finished_at": summary.finished_at,
        "status": summary.status.value,
        "duration_seconds": round(summary.duration_seconds, 2),
        "targets_total": summary.targets_total,
        "targets_processed": summary.targets_processed,
        "reachable": summary.reachable,
        "unreachable": summary.unreachable,
        "incomplete_observations": summary.incomplete,
        "errors_by_type": dict(sorted(summary.error_counts.items())),
        "changes_found": len(changes),
        "interesting_changes": sum(1 for c in changes if c.interesting),
        "raw_only_changes_suppressed": summary.raw_only_changes,
        "changes_by_type": dict(sorted(by_type.items())),
        "changes": [c.to_dict() for c in changes],
    }


def write_report(path: Path, report: dict[str, Any]) -> None:
    """Write JSON atomically (temp file + rename), so readers never see a half-written file."""
    path = path.resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(report, handle, indent=2, ensure_ascii=False)
            handle.write("\n")
        os.replace(tmp_name, path)
    except BaseException:
        Path(tmp_name).unlink(missing_ok=True)
        raise
