"""End-to-end continuous-operations lifecycle test. Fully offline (local lab, mock AI)."""

import asyncio
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from aiohttp import web

from shadow_scan.ops.lifecycle import LifecycleManager
from shadow_scan.ops.maintenance import backup, export_program, validate_export
from shadow_scan.ops.opsdb import OpsStore
from shadow_scan.ops.runner import RunnerComponents, UnifiedRunner
from shadow_scan.ops.workspace import WorkspaceManager
from shadow_scan.database import Database
from shadow_scan.secanalysis.ai import MockProvider


class Lab:
    """A mutable local application simulating successive deployments."""

    def __init__(self):
        self.phase = "A"
        self.port = 0
        self._runner = None

    async def _handle(self, request):
        origin = request.headers.get("Origin")
        path = request.path
        if path == "/static/app.js":
            js = 'fetch("/api/status");'
            if self.phase in ("B", "C", "E"):
                js += 'fetch("/api/internal/export?account_id=1");'
            return web.Response(text=js, content_type="application/javascript")
        if path == "/api/status":
            headers = {}
            # Reflected credentialed CORS present in A/B/C and E; "fixed" in D.
            if origin and self.phase != "D":
                headers["Access-Control-Allow-Origin"] = origin
                headers["Access-Control-Allow-Credentials"] = "true"
            return web.Response(text='{"ok":true}', content_type="application/json", headers=headers)
        if path == "/api/internal/export":
            return web.Response(text='{"rows":[]}', content_type="application/json")
        body = '<html><head><title>Home</title><script src="/static/app.js"></script></head><body>' \
               '<a href="/api/status">s</a></body></html>'
        return web.Response(text=body, content_type="text/html")

    async def start(self):
        app = web.Application(); app.router.add_route("*", "/{t:.*}", self._handle)
        self._runner = web.AppRunner(app, access_log=None); await self._runner.setup()
        site = web.TCPSite(self._runner, "127.0.0.1", 0); await site.start()
        self.port = site._server.sockets[0].getsockname()[1]

    async def stop(self):
        if self._runner:
            await self._runner.cleanup()


class OpsLifecycleE2E(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.lab = Lab(); await self.lab.start()
        self.mgr = WorkspaceManager(self.base)
        self.mgr.create("lab", name="Lab", platform="generic")
        # Point scope at the local lab (http, port-scoped) and enable a fast stage set.
        scope = self.mgr.workspace("lab").config_dir / "scope.yaml"
        scope.write_text(f"scope_roots:\n  - http://127.0.0.1:{self.lab.port}\n  - '@scheme http'\n", encoding="utf-8")
        prog = self.mgr.workspace("lab").config_dir / "program.yaml"
        text = prog.read_text(encoding="utf-8")
        text = text.replace(
            "enabled_stages: [preflight, discovery, dns, monitor, services, urls, crawl, javascript,\n"
            "                 enrichment, correlation, security_analysis, validation, ai_analysis,\n"
            "                 review, reporting, notifications]",
            "enabled_stages: [preflight, dns, crawl, javascript, correlation, security_analysis, "
            "validation, ai_analysis, reporting, notifications]")
        text = text.replace("notify_min_priority: 80", "notify_min_priority: 50")
        prog.write_text(text, encoding="utf-8")

    async def asyncTearDown(self):
        await self.lab.stop(); self.tmp.cleanup()

    def _runner(self, **kw):
        config = self.mgr.load("lab")
        ws = self.mgr.workspace("lab")
        comps = RunnerComponents(ai_provider=MockProvider())
        return UnifiedRunner(ws, config, comps, verify_tls=False, **kw)

    def query(self, sql, *p):
        with closing(sqlite3.connect(self.mgr.workspace("lab").db_path)) as c:
            c.row_factory = sqlite3.Row
            return c.execute(sql, p).fetchall()

    async def test_full_lifecycle(self):
        ws = self.mgr.workspace("lab")

        # --- Deployment A: baseline ---
        self.lab.phase = "A"
        r1 = await self._runner().run()
        self.assertEqual(r1.status, "completed")
        self.assertGreaterEqual(r1.summary["security_findings"], 1)
        # CORS reflected finding exists.
        cors = self.query("SELECT dedup_key, title FROM security_findings WHERE category='cors'")
        self.assertTrue(cors)
        cors_key = cors[0]["dedup_key"]
        # first_seen recorded in lifecycle state.
        self.assertTrue(self.query("SELECT 1 FROM ops_finding_state WHERE dedup_key=?", cors_key))
        # A run report was written.
        self.assertTrue(list(ws.reports_dir.glob("run-*.json")))

        # --- Deployment B: new JS endpoint appears ---
        self.lab.phase = "B"
        r2 = await self._runner().run()
        self.assertEqual(r2.status, "completed")
        js_eps = {r[0] for r in self.query("SELECT value FROM js_findings")}
        self.assertTrue(any("/api/internal/export" in v for v in js_eps))

        # --- Researcher confirms the CORS finding (manual lifecycle action) ---
        with Database(ws.db_path) as db:
            store = OpsStore(db); store.ensure_schema("t")
            mgr = LifecycleManager(store, "lab")
            with db.transaction():
                self.assertTrue(mgr.transition(cors_key, "triaged", "t"))
                self.assertTrue(mgr.transition(cors_key, "investigating", "t"))
                self.assertTrue(mgr.transition(cors_key, "confirmed", "t"))
        self.assertEqual(self.query("SELECT lifecycle FROM ops_finding_state WHERE dedup_key=?", cors_key)[0][0],
                         "confirmed")

        # --- Deployment D: vulnerability fixed (CORS reflection removed) ---
        self.lab.phase = "D"
        r4 = await self._runner().run()
        self.assertEqual(r4.status, "completed")
        # The confirmed finding is no longer observed -> auto-resolved, and reported as resolved.
        state = self.query("SELECT lifecycle, resolved_at FROM ops_finding_state WHERE dedup_key=?", cors_key)[0]
        self.assertEqual(state["lifecycle"], "resolved")
        self.assertIsNotNone(state["resolved_at"])
        self.assertIn(cors_key, r4.resolved)

        # --- Deployment E: regression (CORS reflection reintroduced) ---
        self.lab.phase = "E"
        r5 = await self._runner().run()
        self.assertEqual(r5.status, "completed")
        state = self.query("SELECT lifecycle, regressed_count FROM ops_finding_state WHERE dedup_key=?", cors_key)[0]
        self.assertEqual(state["regressed_count"], 1)
        self.assertIn(cors_key, r5.regressions)
        # Same lineage, no duplicate finding row.
        self.assertEqual(len(self.query("SELECT 1 FROM security_findings WHERE dedup_key=?", cors_key)), 1)
        events = [e[0] for e in self.query("SELECT event FROM ops_finding_timeline WHERE dedup_key=? ORDER BY id", cors_key)]
        self.assertIn("finding_regressed", events)

        # --- Export program intelligence + backup DB ---
        with Database(ws.db_path) as db:
            exp = export_program(db, "lab", ws.exports_dir / "intel.json")
            bak = backup(db, ws.exports_dir / "backup.db")
        self.assertTrue(validate_export(exp).ok)
        with closing(sqlite3.connect(bak)) as c:
            self.assertGreaterEqual(c.execute("SELECT COUNT(*) FROM security_findings").fetchone()[0], 1)

    async def test_run_lock_blocks_concurrent(self):
        from shadow_scan.ops.lock import RunLock, LockError
        ws = self.mgr.workspace("lab"); ws.ensure_runtime()
        held = RunLock(ws.lock_path); held.acquire()
        try:
            with self.assertRaises(LockError):
                await self._runner().run()
        finally:
            held.release()

    async def test_interrupt_and_resume(self):
        # Interrupt during the recon portion, then resume to completion.
        runner = self._runner()
        orig = runner._run_security
        async def boom(): raise asyncio.CancelledError()
        runner._run_security = boom
        with self.assertRaises(asyncio.CancelledError):
            await runner.run()
        unfinished = self.query("SELECT status FROM ops_runs ORDER BY id DESC LIMIT 1")[0][0]
        self.assertEqual(unfinished, "interrupted")
        # A fresh runner with resume completes.
        r = await self._runner(resume=True).run()
        self.assertEqual(r.status, "completed")


if __name__ == "__main__":
    unittest.main()
