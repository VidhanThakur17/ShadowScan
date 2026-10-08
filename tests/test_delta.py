import unittest
from dataclasses import replace

from shadow_scan.delta import ContentComparison, compare_content, detect_changes, sort_changes
from shadow_scan.models import AssetHistory, Change, ChangeType, ErrorType, PreviousObservation, ProbeResult
from shadow_scan.scoring import PRIORITY, assess
from shadow_scan.similarity import build_sketch
from shadow_scan.utils import normalize_target

TARGET = normalize_target("admin.example.com")


def current(**overrides) -> ProbeResult:
    values = dict(
        target=TARGET, url="https://admin.example.com/", checked_at="2026-01-02T00:00:00.000Z",
        final_url="https://admin.example.com/", status_code=200, body_sha256="a" * 64,
        normalized_sha256="n" * 64, title="Admin", server_header="nginx",
    )
    values.update(overrides)
    return ProbeResult(**values)


def unreachable(error: ErrorType) -> ProbeResult:
    return current(status_code=None, final_url=None, body_sha256=None, normalized_sha256=None, title=None,
                   server_header=None, error_type=error, error_message=str(error))


PREVIOUS = PreviousObservation(
    id=1, checked_at="2026-01-01T00:00:00.000Z", status_code=200, body_sha256="a" * 64,
    title="Admin", redirect_location=None, final_url="https://admin.example.com/", error_type=None,
    normalized_sha256="n" * 64, server_header="nginx", observation_complete=True,
)
DNS_DOWN = replace(PREVIOUS, status_code=None, body_sha256=None, normalized_sha256=None, title=None,
                   final_url=None, server_header=None, error_type="dns_failure", observation_complete=False)


def types(changes) -> list[ChangeType]:
    return [c.change_type for c in changes]


def changed_content(similarity: float | None) -> ContentComparison:
    return ContentComparison(comparable=True, baseline_id=1, raw_changed=True, content_changed=True, similarity=similarity)


class BasicDeltaTests(unittest.TestCase):
    def test_first_seen_asset(self) -> None:
        changes = detect_changes(current(), None)
        self.assertEqual(types(changes), [ChangeType.NEW_ASSET])
        self.assertEqual(changes[0].to_dict()["target"], "admin.example.com")
        self.assertEqual(changes[0].review_priority, PRIORITY["new_asset_reachable"])
        self.assertFalse(changes[0].interesting)

    def test_unchanged_response(self) -> None:
        unchanged = ContentComparison(comparable=True, baseline_id=1, similarity=1.0)
        self.assertEqual(detect_changes(current(), PREVIOUS, PREVIOUS, unchanged), [])

    def test_server_header_change_alone_is_low_priority(self) -> None:
        changes = detect_changes(current(server_header="Apache"), PREVIOUS, PREVIOUS)
        self.assertEqual(types(changes), [ChangeType.SERVER_HEADER_CHANGED])
        self.assertEqual(changes[0].review_priority, PRIORITY["server_header_changed"])

    def test_redirect_change_does_not_also_report_redirect_body_change(self) -> None:
        old = replace(PREVIOUS, status_code=302, redirect_location="https://a.example.com/")
        new = current(status_code=302, redirect_location="https://b.example.com/", title="Moved")
        changes = detect_changes(new, old, old, changed_content(0.5))
        self.assertEqual(types(changes), [ChangeType.REDIRECT_CHANGED])
        self.assertTrue(changes[0].fields["host_changed"])
        self.assertEqual(changes[0].review_priority, PRIORITY["redirect_changed_host"])

    def test_title_change(self) -> None:
        comparable = ContentComparison(comparable=True, baseline_id=1, similarity=1.0)
        changes = detect_changes(current(title="Login"), PREVIOUS, PREVIOUS, comparable)
        self.assertEqual(types(changes), [ChangeType.TITLE_CHANGED])
        self.assertEqual(changes[0].fields, {"old": "Admin", "new": "Login"})


class StatusTransitionTests(unittest.TestCase):
    def status_change(self, old: int, new: int) -> Change:
        changes = detect_changes(current(status_code=new), replace(PREVIOUS, status_code=old), PREVIOUS)
        self.assertEqual(types(changes), [ChangeType.STATUS_CHANGED])
        return changes[0]

    def test_404_to_200_is_interesting(self) -> None:
        change = self.status_change(404, 200)
        self.assertTrue(change.interesting)
        self.assertEqual(change.review_priority, 85)
        self.assertIn("missing", change.reason)
        payload = change.to_dict()
        self.assertEqual((payload["old_status"], payload["new_status"]), (404, 200))

    def test_403_to_200_is_interesting(self) -> None:
        change = self.status_change(403, 200)
        self.assertTrue(change.interesting)
        self.assertEqual(change.review_priority, 95)
        self.assertEqual(change.reason, "Previously forbidden endpoint (403) now returns HTTP 200")

    def test_other_interesting_transitions(self) -> None:
        for old, new in ((401, 200), (503, 200), (302, 200), (200, 401), (200, 403)):
            with self.subTest(old=old, new=new):
                self.assertTrue(self.status_change(old, new).interesting)

    def test_uninteresting_transitions(self) -> None:
        for old, new in ((200, 404), (200, 500), (404, 500), (301, 302)):
            with self.subTest(old=old, new=new):
                self.assertFalse(self.status_change(old, new).interesting)

    def test_status_change_folds_related_differences_into_context(self) -> None:
        redirected = replace(PREVIOUS, status_code=302, redirect_location="https://sso.example.com/", title=None)
        changes = detect_changes(
            current(status_code=200, title="Dashboard"), redirected, PREVIOUS, changed_content(0.1),
        )
        # One event; no separate redirect/title/content events.
        self.assertEqual(types(changes), [ChangeType.STATUS_CHANGED])
        context = changes[0].fields["context"]
        self.assertEqual(context["redirect"], {"old": "https://sso.example.com/", "new": None})
        self.assertEqual(context["title"], {"old": None, "new": "Dashboard"})
        self.assertEqual(context["content"]["magnitude"], "major")
        self.assertEqual(changes[0].reason, "Endpoint that previously redirected (302) now serves content directly (HTTP 200)")


class AvailabilityAndErrorTests(unittest.TestCase):
    def test_reachable_to_unreachable(self) -> None:
        changes = detect_changes(unreachable(ErrorType.CONNECTION_REFUSED), PREVIOUS, PREVIOUS)
        self.assertEqual(types(changes), [ChangeType.AVAILABILITY_CHANGED])
        self.assertEqual(changes[0].fields["old"]["state"], "reachable")
        self.assertEqual(changes[0].fields["new"],
                         {"state": "unreachable", "status_code": None, "error_type": "connection_refused"})
        self.assertFalse(changes[0].interesting)

    def test_unreachable_to_reachable_is_single_interesting_event(self) -> None:
        changes = detect_changes(current(), DNS_DOWN, PREVIOUS, changed_content(0.2))
        # No error_changed, status_changed or content noise alongside the availability flip.
        self.assertEqual(types(changes), [ChangeType.AVAILABILITY_CHANGED])
        self.assertTrue(changes[0].interesting)
        self.assertEqual(changes[0].review_priority, PRIORITY["newly_reachable_success"])
        self.assertEqual(changes[0].fields["old"]["error_type"], "dns_failure")

    def test_dns_to_connection_refused_is_error_changed(self) -> None:
        changes = detect_changes(unreachable(ErrorType.CONNECTION_REFUSED), DNS_DOWN)
        self.assertEqual(types(changes), [ChangeType.ERROR_CHANGED])
        payload = changes[0].to_dict()
        self.assertEqual((payload["old_error"], payload["new_error"]), ("dns_failure", "connection_refused"))
        self.assertTrue(changes[0].interesting)

    def test_dns_lost_is_not_interesting(self) -> None:
        refused = replace(DNS_DOWN, error_type="connection_refused")
        changes = detect_changes(unreachable(ErrorType.DNS_FAILURE), refused)
        self.assertEqual(types(changes), [ChangeType.ERROR_CHANGED])
        self.assertFalse(changes[0].interesting)

    def test_still_unreachable_same_error_is_quiet(self) -> None:
        self.assertEqual(detect_changes(unreachable(ErrorType.DNS_FAILURE), DNS_DOWN), [])


class ContentClassificationTests(unittest.TestCase):
    def content_change(self, similarity: float | None) -> Change:
        changes = detect_changes(
            current(normalized_sha256="m" * 64, body_sha256="b" * 64), PREVIOUS, PREVIOUS,
            changed_content(similarity), AssetHistory(10, 9, 3),
        )
        self.assertEqual(len(changes), 1)
        return changes[0]

    def test_major_similarity_change(self) -> None:
        change = self.content_change(0.42)
        self.assertEqual(change.change_type, ChangeType.CONTENT_CHANGED_MAJOR)
        self.assertEqual(change.fields["magnitude"], "major")
        self.assertEqual(change.review_priority, PRIORITY["content_major"])
        self.assertEqual(change.fields["history"], {"observations": 10, "content_comparisons": 9,
                                                    "content_changes": 3, "change_ratio": 0.3333})

    def test_minor_similarity_change(self) -> None:
        change = self.content_change(0.9)
        self.assertEqual(change.change_type, ChangeType.CONTENT_CHANGED_MINOR)
        self.assertEqual(change.fields["magnitude"], "minor")
        self.assertEqual(change.review_priority, PRIORITY["content_minor"])

    def test_trivial_similarity_change(self) -> None:
        change = self.content_change(0.995)
        self.assertEqual(change.change_type, ChangeType.CONTENT_CHANGED_MINOR)
        self.assertEqual(change.fields["magnitude"], "trivial")
        self.assertEqual(change.review_priority, PRIORITY["content_trivial"])

    def test_unmeasurable_change_is_major_with_lower_priority(self) -> None:
        change = self.content_change(None)
        self.assertEqual(change.change_type, ChangeType.CONTENT_CHANGED_MAJOR)
        self.assertEqual(change.fields["magnitude"], "unmeasured")
        self.assertEqual(change.review_priority, PRIORITY["content_unmeasured"])

    def test_thresholds_are_configurable(self) -> None:
        changes = detect_changes(current(), PREVIOUS, PREVIOUS, changed_content(0.9),
                                 trivial_threshold=0.99, major_threshold=0.95)
        self.assertEqual(changes[0].fields["magnitude"], "major")


class CompareContentTests(unittest.TestCase):
    SKETCH = build_sketch("<p>" + " ".join(f"w{i}" for i in range(400)) + "</p>", 1 << 20)

    def test_raw_changed_normalized_same_is_suppressed_noise(self) -> None:
        loads = []
        result = compare_content(current(body_sha256="b" * 64), PREVIOUS, lambda: loads.append(1))
        self.assertTrue(result.raw_only)
        self.assertFalse(result.content_changed)
        self.assertEqual(result.similarity, 1.0)
        self.assertEqual(loads, [], "baseline sketch must not be loaded when content is unchanged")

    def test_normalized_change_uses_sketch_similarity(self) -> None:
        changed = build_sketch("<p>" + " ".join(f"x{i}" for i in range(400)) + "</p>", 1 << 20)
        result = compare_content(
            current(body_sha256="b" * 64, normalized_sha256="m" * 64, similarity_sketch=changed),
            PREVIOUS, lambda: self.SKETCH,
        )
        self.assertTrue(result.content_changed)
        self.assertLess(result.similarity, 0.2)

    def test_incomplete_observation_is_never_compared(self) -> None:
        truncated = current(body_sha256="b" * 64, normalized_sha256=None, body_truncated=True,
                            error_type=ErrorType.RESPONSE_TOO_LARGE)
        self.assertTrue(truncated.http_reachable)
        self.assertFalse(truncated.observation_complete)
        result = compare_content(truncated, PREVIOUS, lambda: self.SKETCH)
        self.assertFalse(result.comparable)
        self.assertEqual(detect_changes(truncated, PREVIOUS, PREVIOUS, result), [])

    def test_normalized_vs_raw_is_never_mixed(self) -> None:
        # Current text grew past the normalization limit: fall back to raw-vs-raw.
        same_raw = compare_content(current(normalized_sha256=None), PREVIOUS, lambda: None)
        self.assertFalse(same_raw.content_changed)
        new_raw = compare_content(current(normalized_sha256=None, body_sha256="c" * 64), PREVIOUS, lambda: None)
        self.assertTrue(new_raw.content_changed)
        self.assertIsNone(new_raw.similarity)


class PriorityTests(unittest.TestCase):
    def test_priorities_follow_documented_order(self) -> None:
        def scored(change_type: ChangeType, **fields) -> int:
            return assess(Change(change_type, "t", fields)).review_priority

        ranking = [
            scored(ChangeType.STATUS_CHANGED, old_status=403, new_status=200),
            scored(ChangeType.STATUS_CHANGED, old_status=404, new_status=200),
            scored(ChangeType.AVAILABILITY_CHANGED, new={"state": "reachable", "status_code": 200}),
            scored(ChangeType.CONTENT_CHANGED_MAJOR, magnitude="major"),
            scored(ChangeType.NEW_ASSET, reachable=True),
            scored(ChangeType.TITLE_CHANGED),
            scored(ChangeType.SERVER_HEADER_CHANGED),
            scored(ChangeType.CONTENT_CHANGED_MINOR, magnitude="trivial"),
        ]
        self.assertEqual(ranking, sorted(ranking, reverse=True))
        self.assertEqual(len(set(ranking)), len(ranking))

    def test_all_priorities_in_range_and_interesting_is_never_low(self) -> None:
        self.assertTrue(all(0 <= value <= 100 for value in PRIORITY.values()))
        samples = [
            Change(ChangeType.STATUS_CHANGED, "t", {"old_status": o, "new_status": n})
            for o in (200, 301, 401, 403, 404, 500, 503) for n in (200, 302, 401, 403, 404, 500)
        ] + [Change(ChangeType.ERROR_CHANGED, "t", {"old_error": "dns_failure", "new_error": "connection_refused"})]
        for change in map(assess, samples):
            if change.interesting:
                self.assertGreaterEqual(change.review_priority, 45, change)

    def test_report_ordering_is_by_priority_then_target(self) -> None:
        changes = [assess(c) for c in (
            Change(ChangeType.TITLE_CHANGED, "b.example.com"),
            Change(ChangeType.STATUS_CHANGED, "z.example.com", {"old_status": 403, "new_status": 200}),
            Change(ChangeType.TITLE_CHANGED, "a.example.com"),
        )]
        self.assertEqual([c.target for c in sort_changes(changes)], ["z.example.com", "a.example.com", "b.example.com"])


if __name__ == "__main__":
    unittest.main()
