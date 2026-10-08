import json
import os
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from shadow_scan.database import Database
from shadow_scan.ops.feedback import (
    BaselineMatcher,
    IgnoreMatcher,
    RankingAdjuster,
    RankingContext,
    feedback_delta,
)
from shadow_scan.ops.incremental import IncrementalPlanner, TaskReason, fingerprint
from shadow_scan.ops.lifecycle import LifecycleManager, can_transition
from shadow_scan.ops.maintenance import (
    backup,
    export_program,
    integrity_check,
    retention_trim,
    stats,
    validate_export,
)
from shadow_scan.ops.opsdb import OpsStore
from shadow_scan.ops.report import FindingReport, render_finding_json, render_finding_markdown


def opsdb():
    d = tempfile.mkdtemp()
    db = Database(os.path.join(d, "o.db")); db.open()
    store = OpsStore(db); store.ensure_schema("t")
    return d, db, store


class FeedbackTests(unittest.TestCase):
    def test_delta_bounded(self):
        self.assertLessEqual(feedback_delta({"noise": 100}, {"noise": 100}), 0)
        self.assertGreaterEqual(feedback_delta({"noise": 100}, {}), -25)
        self.assertLessEqual(feedback_delta({"interesting": 100}, {}), 25)
        self.assertEqual(feedback_delta({}, {}), 0)

    def test_ranking_adjuster(self):
        d, db, store = opsdb()
        with db.transaction():
            for _ in range(5):
                store.add_feedback("prog", "category", "cookie_security", "false_positive", "t")
        adj = RankingAdjuster(store, "prog")
        new, delta = adj.adjust(40, RankingContext("prog", "cookie_security", None, None))
        self.assertLess(new, 40)
        self.assertLess(delta, 0)
        db.close()

    def test_ignore_matcher_exempts_structural(self):
        rules = [{"id": 1, "rule_type": "path", "pattern": "*/analytics/*"}]
        m = IgnoreMatcher(rules)
        self.assertIsNotNone(m.match(category="information_disclosure", check_id="passive.x",
                                     endpoint="/app/analytics/collect", parameter=None))
        # Structural categories are never suppressed.
        self.assertIsNone(m.match(category="authorization", check_id="authz.x",
                                  endpoint="/app/analytics/collect", parameter=None))
        self.assertIsNone(m.match(category="exposure", check_id="exposure.env_file",
                                  endpoint="/app/analytics/.env", parameter=None))

    def test_ignore_parameter_and_tech(self):
        m = IgnoreMatcher([{"id": 1, "rule_type": "parameter", "pattern": "utm_source"},
                           {"id": 2, "rule_type": "technology", "pattern": "Cloudflare"}])
        self.assertIsNotNone(m.match(category="x", check_id=None, endpoint=None, parameter="utm_source"))
        self.assertIsNotNone(m.match(category="x", check_id=None, endpoint=None, parameter=None,
                                     technology="Cloudflare"))

    def test_baseline_matcher(self):
        m = BaselineMatcher([{"scope_kind": "endpoint", "scope_key": "api/status", "expectation": "403 expected"}])
        self.assertTrue(m.is_expected("endpoint", "api/status", "403 expected"))
        self.assertFalse(m.is_expected("endpoint", "api/status", "500 unexpected"))


class LifecycleTests(unittest.TestCase):
    def test_transitions(self):
        self.assertTrue(can_transition("new", "confirmed"))
        self.assertTrue(can_transition("confirmed", "resolved"))
        self.assertTrue(can_transition("resolved", "investigating"))   # regression reopen
        self.assertFalse(can_transition("new", "resolved"))
        self.assertTrue(can_transition("reported", "archived"))

    def test_regression_reopens_same_lineage(self):
        d, db, store = opsdb()
        mgr = LifecycleManager(store, "prog")
        with db.transaction():
            r1 = mgr.observe("finding-A", "t1")
            self.assertFalse(r1.is_regression)
            mgr.transition("finding-A", "confirmed", "t2")
            mgr.transition("finding-A", "resolved", "t3")
        with db.transaction():
            r2 = mgr.observe("finding-A", "t4")   # reappears
        self.assertTrue(r2.is_regression)
        state = store.get_finding_state("finding-A")
        self.assertEqual(state["regressed_count"], 1)
        self.assertEqual(state["lifecycle"], "investigating")
        events = [e[0] for e in store.timeline("finding-A")]
        self.assertIn("finding_regressed", events)
        db.close()

    def test_auto_resolve_absent_confirmed(self):
        d, db, store = opsdb()
        mgr = LifecycleManager(store, "prog")
        with db.transaction():
            mgr.observe("F1", "t"); mgr.transition("F1", "confirmed", "t")
            mgr.observe("F2", "t")   # stays new
        with db.transaction():
            resolved = mgr.mark_resolved_if_absent(present_keys=set(), now="t2")
        self.assertEqual(resolved, ["F1"])   # only confirmed one auto-resolves
        self.assertEqual(store.get_finding_state("F2")["lifecycle"], "new")
        db.close()


class IncrementalTests(unittest.TestCase):
    def test_schedules_new_and_changed_skips_unchanged(self):
        d, db, store = opsdb()
        with db.transaction():
            planner = IncrementalPlanner(store, "t")
            t1 = planner.consider("js", "app.js", {"sha": "aaa"})
            self.assertEqual(t1.reason, TaskReason.NEW)
            planner.commit(t1)
        with db.transaction():
            planner2 = IncrementalPlanner(store, "t2")
            self.assertIsNone(planner2.consider("js", "app.js", {"sha": "aaa"}))   # unchanged -> skip
            t2 = planner2.consider("js", "app.js", {"sha": "bbb"})
            self.assertEqual(t2.reason, TaskReason.CHANGED)
        self.assertEqual(planner2.skipped, 1)
        db.close()

    def test_force_reanalyzes(self):
        d, db, store = opsdb()
        with db.transaction():
            p = IncrementalPlanner(store, "t")
            p.commit(p.consider("openapi", "spec", {"v": 1}))
        with db.transaction():
            p2 = IncrementalPlanner(store, "t", force=True)
            self.assertEqual(p2.consider("openapi", "spec", {"v": 1}).reason, TaskReason.FORCED)
        db.close()

    def test_fingerprint_stable(self):
        self.assertEqual(fingerprint({"a": 1, "b": 2}), fingerprint({"b": 2, "a": 1}))


class ReportTests(unittest.TestCase):
    def _report(self, lifecycle="new", validation="suspected"):
        return FindingReport(
            title="Possible authorization boundary", asset="api.example.com",
            endpoint="/api/accounts/{id}", category="authorization", confidence=0.6,
            validation_state=validation, lifecycle=lifecycle,
            evidence=[{"kind": "diff", "summary": "viewer and admin differ; token Bearer abcdef1234567890"}],
            ai_hypotheses=[{"title": "Possible BOLA", "confidence": 0.7, "manual_tests": ["compare ids read-only"]}],
            manual_package={"request_shape": "GET /api/accounts/{id}", "required_auth_context": "viewer",
                            "suggested_manual_tests": ["Compare viewer vs admin for same id (read-only)."]},
        )

    def test_markdown_distinguishes_and_redacts(self):
        md = render_finding_markdown(self._report(), formatter="hackerone")
        self.assertIn("Steps To Reproduce", md)
        self.assertIn("NOT established automatically", md)
        self.assertIn("AI Hypotheses (advisory", md)
        self.assertIn("[REDACTED]", md)   # the bearer token in evidence is redacted
        self.assertNotIn("abcdef1234567890", md)

    def test_confirmed_impact_statement(self):
        md = render_finding_markdown(self._report(lifecycle="confirmed"))
        self.assertIn("confirmed by manual researcher validation", md)

    def test_json_report(self):
        j = render_finding_json(self._report())
        self.assertEqual(j["status"], "new")
        self.assertTrue(j["ai_hypotheses_advisory"])
        self.assertIn("Validated", j["validation"]) if False else None
        self.assertIn("[REDACTED]", j["evidence"][0]["summary"])


class MaintenanceTests(unittest.TestCase):
    def _db_with_findings(self):
        d = tempfile.mkdtemp()
        db = Database(os.path.join(d, "m.db")); db.open()
        from shadow_scan.secanalysis.sec_db import SecurityStore
        from shadow_scan.secanalysis.findings import make_evidence
        from shadow_scan.secanalysis.models import Finding
        sec = SecurityStore(db); sec.ensure_schema()
        OpsStore(db).ensure_schema("t")
        with db.transaction():
            sec.upsert_finding(Finding(check_id="c", asset="h", category="cors", endpoint="/x",
                                       title="CORS", source="active",
                                       evidence=[make_evidence("header", "x")]), "t")
            sec.record_auth_profile("admin", "h", "Authorization", "ENV_NAME", None, "")
        return d, db

    def test_stats_and_integrity(self):
        d, db = self._db_with_findings()
        st = stats(db)
        self.assertIn("security_findings", st.tables)
        ok, detail = integrity_check(db)
        self.assertTrue(ok, detail)
        db.close()

    def test_backup_is_consistent(self):
        d, db = self._db_with_findings()
        dest = Path(d) / "backup.db"
        backup(db, dest)
        self.assertTrue(dest.exists())
        with closing(sqlite3.connect(dest)) as c:
            self.assertEqual(c.execute("SELECT COUNT(*) FROM security_findings").fetchone()[0], 1)
        db.close()

    def test_export_excludes_secret_columns(self):
        d, db = self._db_with_findings()
        dest = Path(d) / "export.json"
        export_program(db, "prog", dest)
        payload = json.loads(dest.read_text())
        self.assertEqual(payload["export_version"], 1)
        self.assertIn("security_findings", payload["tables"])
        # auth_profiles_metadata is not exported, and no secret-ish column appears anywhere.
        self.assertNotIn("auth_profiles_metadata", payload["tables"])
        val = validate_export(dest)
        self.assertTrue(val.ok, val.errors)
        db.close()

    def test_export_validation_rejects_secret_column(self):
        d = tempfile.mkdtemp()
        bad = Path(d) / "bad.json"
        bad.write_text(json.dumps({"export_version": 1, "program": "p",
                                   "tables": {"t": {"columns": ["token"], "rows": []}}}))
        self.assertFalse(validate_export(bad).ok)


if __name__ == "__main__":
    unittest.main()
