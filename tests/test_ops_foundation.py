import json
import os
import tempfile
import time
import unittest
from pathlib import Path

from shadow_scan.database import Database
from shadow_scan.ops.guardrails import GuardrailState, ResourceLimits, disk_ok
from shadow_scan.ops.lock import LockError, RunLock, is_stale, read_lock, LockInfo
from shadow_scan.ops.migrate import MIGRATIONS, current_version, migrate, pending
from shadow_scan.ops.notify import (
    ConsoleProvider,
    Event,
    EventType,
    FileProvider,
    NotificationConfig,
    Notifier,
    WebhookProvider,
    build_providers,
)
from shadow_scan.ops.opsdb import OpsStore
from shadow_scan.ops.retry import Backoff, RetryClass, classify, should_retry
from shadow_scan.ops.workspace import WorkspaceManager, validate_config


class MigrationTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.db = Database(os.path.join(self.dir, "m.db")); self.db.open()

    def tearDown(self):
        self.db.close()

    def test_applies_and_is_idempotent(self):
        applied = migrate(self.db, "t")
        self.assertEqual(applied, [m.id for m in MIGRATIONS])
        self.assertEqual(current_version(self.db.conn), max(m.id for m in MIGRATIONS))
        self.assertEqual(migrate(self.db, "t2"), [])      # nothing pending on rerun
        self.assertEqual(pending(self.db.conn), [])

    def test_transactional_rollback_on_failure(self):
        from shadow_scan.ops import migrate as mig

        def bad_apply(conn):
            conn.execute("CREATE TABLE ok_partial (x)")   # half-applies...
            conn.execute("THIS IS NOT SQL")               # ...then fails -> must roll back the table

        bad = mig.Migration(999, "bad", bad_apply)
        original = mig.MIGRATIONS
        mig.MIGRATIONS = (*original, bad)
        try:
            with self.assertRaises(Exception):
                migrate(self.db, "t")
            # The failed migration's partial table must have been rolled back, and 999 not recorded.
            got = self.db.conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='ok_partial'").fetchone()
            self.assertIsNone(got)
            self.assertNotIn(999, mig.applied_ids(self.db.conn))
            # The real migrations before it did apply.
            self.assertIn(1, mig.applied_ids(self.db.conn))
        finally:
            mig.MIGRATIONS = original


class WorkspaceTests(unittest.TestCase):
    def setUp(self):
        self.base = Path(tempfile.mkdtemp())
        self.mgr = WorkspaceManager(self.base)

    def test_create_and_load(self):
        ws = self.mgr.create("acme", name="Acme", platform="hackerone")
        self.assertTrue((ws.config_dir / "program.yaml").exists())
        self.assertTrue((ws.config_dir / "auth.example.yaml").exists())
        self.assertIn("acme", self.mgr.list_programs())
        config = self.mgr.load("acme")
        self.assertEqual(config.platform, "hackerone")
        self.assertIn("example.com", config.scope_roots)

    def test_runtime_paths_isolated_from_config(self):
        ws = self.mgr.workspace("acme")
        self.assertIn("runtime", str(ws.db_path))
        self.assertIn("programs", str(ws.config_dir))

    def test_cli_override_precedence_and_safety_floor(self):
        self.mgr.create("acme")
        # CLI override loosening to safe_active, but env forces passive_only (more restrictive wins).
        os.environ["SHADOWSCAN_GLOBAL_MODE"] = "passive_only"
        try:
            config = self.mgr.load("acme", cli_overrides={"global_mode": "safe_active"})
            self.assertEqual(config.profile.global_mode.value, "passive_only")
        finally:
            del os.environ["SHADOWSCAN_GLOBAL_MODE"]

    def test_validation_catches_unsafe_config(self):
        self.mgr.create("acme")
        config = self.mgr.load("acme", cli_overrides={})
        # Inject problems.
        from shadow_scan.ops.workspace import ProgramConfig
        from shadow_scan.secanalysis.profiles import AuthProfile
        config.profile.allowed_methods = frozenset({"GET", "DELETE"})
        config.profile.auth_profiles = {"x": AuthProfile(name="x", host="")}
        config.profile.nuclei_profiles = ("intrusive",)
        issues = validate_config(config)
        msgs = " ".join(i.message for i in issues)
        self.assertIn("DELETE", msgs)
        self.assertIn("no host binding", msgs)
        self.assertIn("nuclei", msgs)

    def test_invalid_wildcard_scope(self):
        self.mgr.create("acme")
        config = self.mgr.load("acme")
        object.__setattr__(config, "scope_roots", ("*example.com",))
        self.assertTrue(any("wildcard" in i.message for i in validate_config(config)))


class LockTests(unittest.TestCase):
    def setUp(self):
        self.path = Path(tempfile.mkdtemp()) / "run.lock"

    def test_acquire_release(self):
        with RunLock(self.path):
            self.assertIsNotNone(read_lock(self.path))
        self.assertIsNone(read_lock(self.path))

    def test_second_acquire_blocked(self):
        lock = RunLock(self.path); lock.acquire()
        try:
            with self.assertRaises(LockError):
                RunLock(self.path).acquire()
        finally:
            lock.release()

    def test_stale_lock_detected_and_broken(self):
        stale = LockInfo(pid=999999, host="otherhost", started_at=0, heartbeat=0)
        self.assertTrue(is_stale(stale))
        self.path.write_text(json.dumps({"pid": 999999, "host": "otherhost",
                                         "started_at": 0, "heartbeat": 0}), encoding="utf-8")
        with RunLock(self.path):   # breaks the stale lock
            info = read_lock(self.path)
            self.assertEqual(info.pid, os.getpid())

    def test_force_breaks_live_lock(self):
        lock = RunLock(self.path); lock.acquire()
        try:
            with RunLock(self.path, force=True):
                pass
        finally:
            lock.release()


class RetryTests(unittest.TestCase):
    def test_classification(self):
        self.assertEqual(classify("connection_timeout"), RetryClass.RETRYABLE)
        self.assertEqual(classify("nxdomain"), RetryClass.NOT_RETRYABLE)
        self.assertEqual(classify("http_403"), RetryClass.NOT_RETRYABLE)
        self.assertEqual(classify("parser_failure"), RetryClass.STORE_FOR_REVIEW)
        self.assertEqual(classify("policy_denied"), RetryClass.NEVER)
        self.assertEqual(classify(None), RetryClass.NOT_RETRYABLE)

    def test_should_retry_bounded(self):
        self.assertTrue(should_retry("timeout", attempt=1, max_attempts=3))
        self.assertFalse(should_retry("timeout", attempt=3, max_attempts=3))
        self.assertFalse(should_retry("policy_denied", attempt=1))

    def test_backoff_bounded_and_increasing(self):
        import random
        bo = Backoff(base=1, factor=2, max_delay=10, jitter=0)
        rng = random.Random(0)
        self.assertEqual(bo.delay(1, rng=rng), 1)
        self.assertEqual(bo.delay(2, rng=rng), 2)
        self.assertLessEqual(bo.delay(100, rng=rng), 10)


class GuardrailTests(unittest.TestCase):
    def test_request_limit_stops_cleanly(self):
        g = GuardrailState(ResourceLimits(max_total_requests=2))
        self.assertTrue(g.allow_request())
        self.assertTrue(g.allow_request())
        self.assertFalse(g.allow_request())   # limited, not crashed
        self.assertIn("requests", g.limited)
        self.assertTrue(g.is_limited)

    def test_js_and_ai_limits(self):
        g = GuardrailState(ResourceLimits(max_js_files=1, max_ai_calls=0))
        self.assertTrue(g.allow_js())
        self.assertFalse(g.allow_js())
        self.assertFalse(g.allow_ai_call())

    def test_disk_ok(self):
        self.assertTrue(disk_ok(tempfile.gettempdir(), ResourceLimits(min_free_disk_bytes=1)))
        self.assertFalse(disk_ok(tempfile.gettempdir(), ResourceLimits(min_free_disk_bytes=1 << 62)))


class NotificationTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.db = Database(os.path.join(self.dir, "n.db")); self.db.open()
        self.store = OpsStore(self.db); self.store.ensure_schema("t")

    def tearDown(self):
        self.db.close()

    def _notifier(self, providers, **cfg):
        return Notifier(providers, NotificationConfig(**cfg), self.store, "prog")

    def test_filter_min_priority(self):
        sent = []
        n = self._notifier([ConsoleProvider(sent.append)], min_priority=80)
        with self.db.transaction():
            self.assertFalse(n.emit(Event(EventType.NEW_VALIDATED_FINDING, "prog", "low", priority=30), "t"))
            self.assertTrue(n.emit(Event(EventType.NEW_VALIDATED_FINDING, "prog", "high", priority=90,
                                         dedup_key="k1"), "t"))
        self.assertEqual(len(sent), 1)

    def test_dedup_across_runs(self):
        sent = []
        n = self._notifier([ConsoleProvider(sent.append)], min_priority=0)
        ev = Event(EventType.TAKEOVER_CANDIDATE, "prog", "t", priority=90, dedup_key="dup")
        with self.db.transaction():
            self.assertTrue(n.emit(ev, "t"))
        n2 = self._notifier([ConsoleProvider(sent.append)], min_priority=0)
        with self.db.transaction():
            self.assertFalse(n2.emit(ev, "t"))   # already notified
        self.assertEqual(len(sent), 1)

    def test_payload_redacts_secrets(self):
        ev = Event(EventType.NEW_VALIDATED_FINDING, "prog", "token is Bearer abcdef1234567890xyz",
                   priority=90, detail={"body": "password=supersecretvalue", "status": 200})
        payload = ev.safe_payload()
        self.assertIn("[REDACTED]", payload["title"])
        self.assertIn("[REDACTED]", payload["detail"]["body"])
        self.assertEqual(payload["detail"]["status"], 200)

    def test_low_value_events_deferred_to_summary(self):
        sent = []
        n = self._notifier([ConsoleProvider(sent.append)], min_priority=0)
        with self.db.transaction():
            n.emit(Event(EventType.NEW_HOST, "prog", "new host", priority=50, dedup_key="h"), "t")
        self.assertEqual(sent, [])
        self.assertEqual(len(n.deferred), 1)

    def test_file_and_webhook_providers(self):
        path = Path(self.dir) / "notes.jsonl"
        captured = []
        def opener(req, timeout): captured.append(req.data)
        providers = build_providers(("file", "webhook"), file_path=path,
                                    webhook_url="https://hook.example/x", webhook_opener=opener)
        ev = Event(EventType.RUN_COMPLETED, "prog", "done", priority=0, dedup_key="r1")
        n = self._notifier(providers, min_priority=0)
        with self.db.transaction():
            n.emit(ev, "t")
        self.assertTrue(path.exists())
        self.assertTrue(captured and b"run_completed" in captured[0])

    def test_webhook_offline_is_safe(self):
        def boom(req, timeout): raise OSError("offline")
        prov = WebhookProvider("https://x", opener=boom)
        self.assertFalse(prov.send(Event(EventType.RUN_FAILED, "p", "t")))


if __name__ == "__main__":
    unittest.main()
