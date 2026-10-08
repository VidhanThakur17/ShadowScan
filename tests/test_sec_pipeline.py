"""End-to-end security-analysis orchestrator test against a local lab. Offline."""

import asyncio
import os
import socket
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from aiohttp import web
from aiohttp.abc import AbstractResolver

from shadow_scan.config import ScanConfig
from shadow_scan.secanalysis.ai import AIConfig, MockProvider
from shadow_scan.secanalysis.models import EndpointInfo, StageStatus
from shadow_scan.secanalysis.pipeline import SecurityComponents, SecurityConfig, SecurityPipeline
from shadow_scan.secanalysis.profiles import profile_from_dict
from shadow_scan.secanalysis.scope_compat import build_scope  # helper added below


class LocalResolver(AbstractResolver):
    def __init__(self, port): self._port = port
    async def resolve(self, host, port=0, family=socket.AF_INET):
        return [{"hostname": host, "host": "127.0.0.1", "port": self._port,
                 "family": socket.AF_INET, "proto": socket.IPPROTO_TCP, "flags": 0}]
    async def close(self): return None


class LabServer:
    """A controlled vulnerable lab: reflected CORS, open redirect, missing headers,
    and two auth contexts returning intentionally identical privileged objects."""

    def __init__(self):
        self.port = 0
        self._runner = None

    async def _handle(self, request):
        path = request.path
        origin = request.headers.get("Origin")
        if path == "/api/status":
            headers = {}
            if origin:  # reflected-origin CORS with credentials (controlled test behavior)
                headers["Access-Control-Allow-Origin"] = origin
                headers["Access-Control-Allow-Credentials"] = "true"
            return web.Response(text='{"ok":true}', content_type="application/json", headers=headers)
        if path == "/go":
            dest = request.query.get("redirect")
            if dest:
                raise web.HTTPFound(dest)   # controlled open redirect
            return web.Response(text="no dest")
        if path == "/api/accounts/1":
            # Same privileged object regardless of auth -> broken object authz (controlled).
            return web.Response(text='{"id":1,"balance":100,"owner":"alice","admin_token":"x"}',
                                content_type="application/json")
        # default: missing security headers
        return web.Response(text="<html><title>Home</title></html>", content_type="text/html")

    async def start(self):
        app = web.Application(); app.router.add_route("*", "/{t:.*}", self._handle)
        self._runner = web.AppRunner(app, access_log=None); await self._runner.setup()
        site = web.TCPSite(self._runner, "127.0.0.1", 0); await site.start()
        self.port = site._server.sockets[0].getsockname()[1]

    async def stop(self):
        if self._runner: await self._runner.cleanup()


class SecurityPipelineTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.server = LabServer(); await self.server.start()
        self.resolver = LocalResolver(self.server.port)

    async def asyncTearDown(self):
        await self.server.stop(); self.tmp.cleanup()

    def endpoints(self):
        h = "api.example.com"
        return [
            EndpointInfo(host=h, path="/api/status", method="GET", identity=f"GET {h}/api/status",
                         scheme="http", port=self.server.port),
            EndpointInfo(host=h, path="/go", method="GET", param_names=("redirect",),
                         identity=f"GET {h}/go", scheme="http", port=self.server.port),
            EndpointInfo(host=h, path="/api/accounts/1", method="GET", param_names=("id",),
                         identity=f"GET {h}/api/accounts/1", scheme="http", port=self.server.port),
            EndpointInfo(host=h, path="/api/users/5", method="DELETE", param_names=("id",),
                         identity=f"DELETE {h}/api/users/5", scheme="http", port=self.server.port),
        ]

    def config(self, **over):
        scope = build_scope(["api.example.com", f"http://api.example.com:{self.server.port}", "@scheme http"])
        prof = profile_from_dict({"name": "lab", "global_mode": "safe_active",
                                  "allowed_methods": ["GET", "HEAD", "OPTIONS"]})
        scan = ScanConfig(database_path=self.dir / "s.db", concurrency=4, request_timeout=3,
                          total_timeout=5, verify_tls=False)
        cfg = SecurityConfig(scope=scope, scan_config=scan, program=prof,
                             ai=AIConfig(min_priority=50, max_items=10))
        for k, v in over.items():
            setattr(cfg, k, v)
        return cfg

    def query(self, sql, *p):
        with closing(sqlite3.connect(self.dir / "s.db")) as c:
            c.row_factory = sqlite3.Row
            return c.execute(sql, p).fetchall()

    async def test_end_to_end(self):
        cfg = self.config(auth_contexts=())
        comps = SecurityComponents(ai_provider=MockProvider(), aiohttp_resolver=self.resolver)
        pipe = SecurityPipeline(cfg, self.endpoints(), comps)
        run_id = await pipe.run()

        self.assertEqual(self.query("SELECT status FROM sec_runs WHERE id=?", run_id)[0][0], "completed")
        stages = {r[0]: r[1] for r in self.query("SELECT stage,status FROM sec_stages")}
        self.assertTrue(all(v == StageStatus.COMPLETED.value for v in stages.values()), stages)

        findings = {r["category"]: r for r in self.query("SELECT * FROM security_findings")}
        # Reflected credentialed CORS detected by the active check.
        self.assertIn("cors", findings)
        self.assertGreaterEqual(findings["cors"]["review_priority"], 45)
        # Open redirect accepted external destination.
        self.assertIn("open_redirect", findings)
        # Missing security headers (passive).
        self.assertIn("security_headers", findings)
        # DELETE endpoint became a manual-validation finding, never executed.
        manual = self.query("SELECT * FROM security_findings WHERE validation_state='manual_validation_required'")
        self.assertTrue(manual)
        pkgs = self.query("SELECT package FROM manual_validation_items")
        self.assertTrue(pkgs)

        # Policy decisions persisted; DELETE recorded as not executed.
        delete_dec = self.query("SELECT policy, executed FROM security_checks WHERE endpoint='/api/users/5'")
        self.assertTrue(delete_dec)
        self.assertEqual(delete_dec[0]["executed"], 0)

        # AI hypotheses stored for high-priority findings.
        self.assertTrue(self.query("SELECT COUNT(*) FROM ai_analyses")[0][0] >= 1)

        # Attack-path graph populated.
        self.assertTrue(self.query("SELECT COUNT(*) FROM graph_nodes")[0][0] >= 1)
        self.assertTrue(self.query("SELECT COUNT(*) FROM graph_edges")[0][0] >= 1)

    async def test_passive_mode_makes_no_active_findings(self):
        prof = profile_from_dict({"name": "p", "global_mode": "passive_only"})
        cfg = self.config()
        cfg.program = prof
        cfg.enable_active = True
        pipe = SecurityPipeline(cfg, self.endpoints(), SecurityComponents(aiohttp_resolver=self.resolver,
                                                                          ai_provider=MockProvider()))
        await pipe.run()
        # No active check could run, so no reflected-CORS/open-redirect active findings exist.
        active = self.query("SELECT COUNT(*) FROM security_findings WHERE source='active'")[0][0]
        self.assertEqual(active, 0)
        # The total governor request count stays at 0 in passive mode.
        self.assertEqual(pipe._governor.total_requests, 0)

    async def test_auth_context_differential_read_only(self):
        os.environ["LAB_ADMIN_TOK"] = "admintoken123456"
        try:
            prof = profile_from_dict({"name": "lab", "global_mode": "safe_active",
                                      "authentication_profiles": [
                                          {"name": "admin", "host": "api.example.com", "token_env": "LAB_ADMIN_TOK"}]})
            cfg = self.config(auth_contexts=("admin",))
            cfg.program = prof
            pipe = SecurityPipeline(cfg, self.endpoints(),
                                    SecurityComponents(aiohttp_resolver=self.resolver, ai_provider=MockProvider()))
            await pipe.run()
            # anonymous and admin get the same privileged object => authz finding.
            authz = self.query("SELECT * FROM security_findings WHERE category='authorization'")
            self.assertTrue(authz, "expected an authorization differential finding")
        finally:
            del os.environ["LAB_ADMIN_TOK"]

    async def test_interrupted_then_resume(self):
        cfg = self.config()
        pipe = SecurityPipeline(cfg, self.endpoints(),
                                SecurityComponents(aiohttp_resolver=self.resolver, ai_provider=MockProvider()))
        orig = pipe._stage_validation
        async def boom(): raise asyncio.CancelledError()
        pipe._stage_validation = boom
        with self.assertRaises(asyncio.CancelledError):
            await pipe.run()
        self.assertEqual(self.query("SELECT status FROM sec_runs")[0][0], "interrupted")

        pipe2 = SecurityPipeline(self.config(), self.endpoints(),
                                 SecurityComponents(aiohttp_resolver=self.resolver, ai_provider=MockProvider()))
        rid = await pipe2.run(resume=True)
        self.assertEqual(self.query("SELECT status FROM sec_runs WHERE id=?", rid)[0][0], "completed")


if __name__ == "__main__":
    unittest.main()
