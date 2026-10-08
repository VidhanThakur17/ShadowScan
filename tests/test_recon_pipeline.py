"""End-to-end recon pipeline tests, fully offline.

A custom aiohttp resolver maps every hostname to one local aiohttp server, so
multi-host scenarios (new subdomains, revived hosts, admin panels) run without
DNS or internet. DNS resolution and external tools are injected fakes.
"""

import asyncio
import socket
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from aiohttp import web
from aiohttp.abc import AbstractResolver

from shadow_scan.config import ScanConfig
from shadow_scan.recon.crawler import CrawlConfig
from shadow_scan.recon.dns import DnsRecord
from shadow_scan.recon.models import ScopeClass, StageStatus
from shadow_scan.recon.pipeline import ReconComponents, ReconConfig, ReconPipeline
from shadow_scan.recon.recon_db import ReconStore
from shadow_scan.recon.scope import ScopeEngine
from shadow_scan.database import Database


class LocalResolver(AbstractResolver):
    """Maps any hostname -> 127.0.0.1 and overrides the port to the test server."""

    def __init__(self, port: int) -> None:
        self._port = port

    async def resolve(self, host, port=0, family=socket.AF_INET):
        return [{
            "hostname": host, "host": "127.0.0.1", "port": self._port,
            "family": socket.AF_INET, "proto": socket.IPPROTO_TCP, "flags": 0,
        }]

    async def close(self) -> None:
        return None


class FakeResolver:
    """Recon DNS resolver returning scripted DnsRecords per hostname."""

    def __init__(self, table: dict[str, DnsRecord]) -> None:
        self.table = table

    async def resolve(self, hostname: str) -> DnsRecord:
        return self.table.get(hostname, DnsRecord(hostname, status="nxdomain"))


class FakeTool:
    """Stands in for a discovery/url/port adapter without a real binary."""

    def __init__(self, name: str, results: list[str]) -> None:
        self.name = name
        self._results = results

    def available(self) -> bool:
        return True

    def run(self, targets, timeout=0):
        return list(self._results)


# --- scenario server --------------------------------------------------------------------

APP_JS_V1 = 'const api="/api/v1/items";fetch(api);'
APP_JS_V2 = (
    '//# sourceMappingURL=app.js.map\n'
    'const api="/api/v1/items";'
    'fetch("/api/internal/export?account_id=5");'
    'const admin="/admin/dashboard";'
)
SOURCE_MAP = '{"version":3,"sources":["webpack:///src/secret.ts"],"sourcesContent":["const u=\\"/api/internal/keys\\";"]}'
OPENAPI = (
    '{"openapi":"3.0.0","info":{"title":"API"},"paths":{'
    + ",".join(f'"/api/res{i}/{{id}}":{{"get":{{"parameters":[{{"name":"role","in":"query"}}]}}}}' for i in range(25))
    + "}}"
)


def html(title: str, body: str = "", js: bool = False) -> bytes:
    script = '<script src="/static/app.js"></script>' if js else ""
    link = '<link rel="icon" href="/favicon.ico">'
    return f"<html><head><title>{title}</title>{link}{script}</head><body>{body}</body></html>".encode()


class ScenarioServer:
    def __init__(self) -> None:
        self.phase = 1
        self.port = 0
        self.app_js = APP_JS_V1
        self._runner = None

    async def _handle(self, request: web.Request) -> web.StreamResponse:
        host = (request.host or "").split(":")[0]
        path = request.path
        if path == "/static/app.js":
            return web.Response(text=self.app_js, content_type="application/javascript")
        if path == "/static/app.js.map":
            return web.Response(text=SOURCE_MAP, content_type="application/json")
        if path == "/favicon.ico":
            body = b"ICON1" if self.phase == 1 else b"ICON2"
            return web.Response(body=body, content_type="image/x-icon")
        if path == "/openapi.json":
            if host.startswith("api.") and self.phase >= 2:
                return web.Response(text=OPENAPI, content_type="application/json")
            return web.Response(status=404, text="no spec")
        if host.startswith("admin."):
            if self.phase == 1:
                return web.Response(status=404, text="nope")
            return web.Response(body=html("Admin Console", "<a href='/users'>users</a>"), content_type="text/html")
        if host.startswith("api."):
            return web.Response(body=html("API Portal", js=True), content_type="text/html")
        if host.startswith("news."):
            body = f"<p>breaking {self.phase}{'x' * self.phase}</p>" * 5
            return web.Response(body=html("News", body), content_type="text/html")
        if host.startswith("www."):
            # A plain, stable marketing page: produces no recon signals.
            return web.Response(body=html("Welcome", "<p>About us</p>"), content_type="text/html")
        # apex (example.com): home page that loads the shared JS bundle.
        return web.Response(body=html("Home", "<a href='/about'>about</a><a href='http://evil.com/x'>e</a>", js=True),
                            content_type="text/html")

    async def start(self) -> None:
        app = web.Application()
        app.router.add_route("GET", "/{tail:.*}", self._handle)
        self._runner = web.AppRunner(app, access_log=None)
        await self._runner.setup()
        site = web.TCPSite(self._runner, "127.0.0.1", 0)
        await site.start()
        self.port = site._server.sockets[0].getsockname()[1]

    async def stop(self) -> None:
        if self._runner:
            await self._runner.cleanup()


SCOPE_HOSTS = ["example.com", "www.example.com", "admin.example.com", "api.example.com", "news.example.com"]


class ReconPipelineTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.server = ScenarioServer()
        await self.server.start()
        self.resolver = LocalResolver(self.server.port)

    async def asyncTearDown(self) -> None:
        await self.server.stop()
        self.tmp.cleanup()

    def dns_table(self, api_live: bool) -> dict[str, DnsRecord]:
        table = {h: DnsRecord(h, status="resolves", a=("127.0.0.1",)) for h in
                 ["example.com", "www.example.com", "admin.example.com", "news.example.com"]}
        table["api.example.com"] = (DnsRecord("api.example.com", status="resolves", a=("127.0.0.1",))
                                     if api_live else DnsRecord("api.example.com", status="nxdomain"))
        return table

    def make_pipeline(self, *, api_live: bool, discovery: list[str], ports: list[str]) -> ReconPipeline:
        # Scope pins every host to the ephemeral HTTP port so the local server is reachable.
        scope_lines = [f"http://{h}:{self.server.port}" for h in SCOPE_HOSTS] + [
            "http://admin.example.com:8443",   # 8443 is in scope for admin (new-port scenario)
            "@scheme http",
        ]
        scope = ScopeEngine.parse(scope_lines)
        scan = ScanConfig(
            database_path=self.dir / "recon.db", concurrency=4, request_timeout=3,
            total_timeout=5, db_flush_interval=0.05, verify_tls=False,
        )
        config = ReconConfig(
            scope=scope, scan_config=scan, crawl=CrawlConfig(max_depth=1, max_total_urls=50),
            root_domains=("example.com",), port_profile="fast",
        )
        components = ReconComponents(
            resolver=FakeResolver(self.dns_table(api_live)),
            aiohttp_resolver=self.resolver,
            discovery_adapters=[FakeTool("subfinder", discovery)],
            url_adapters=[FakeTool("gau", [f"http://www.example.com:{self.server.port}/search?q=1&redirect=/x"])],
            port_adapters=[FakeTool("naabu", ports)],
            use_real_tools=False,
        )
        return ReconPipeline(config, components)

    def query(self, sql, *params):
        with closing(sqlite3.connect(self.dir / "recon.db")) as conn:
            conn.row_factory = sqlite3.Row
            return conn.execute(sql, params).fetchall()

    async def test_end_to_end_two_runs(self) -> None:
        # ---- Run 1: baseline. api.example.com is dead; admin is 404; app.js v1. ----
        discovery1 = [f"{h}" for h in SCOPE_HOSTS]
        ports1 = [f"{h}:{self.server.port}" for h in ("www.example.com", "example.com")]
        run1 = await self.make_pipeline(api_live=False, discovery=discovery1, ports=ports1).run()
        self.assertEqual(self.query("SELECT status FROM recon_runs WHERE id=?", run1)[0][0], "completed")
        # All stages completed.
        stages = {r[0]: r[1] for r in self.query("SELECT stage, status FROM recon_stages WHERE run_id=?", run1)}
        self.assertTrue(all(v == StageStatus.COMPLETED.value for v in stages.values()), stages)
        # Off-scope URL never stored as in-scope.
        evil = self.query("SELECT scope_class FROM urls WHERE url LIKE '%evil.com%'")
        self.assertTrue(all(r[0] != ScopeClass.IN_SCOPE.value for r in evil))

        # ---- Mutate the world for run 2. ----
        self.server.phase = 2
        self.server.app_js = APP_JS_V2
        discovery2 = discovery1 + ["secret-dev.example.com"]           # a brand-new subdomain
        ports2 = ports1 + [f"api.example.com:{self.server.port}", f"admin.example.com:8443"]  # new ports
        run2 = await self.make_pipeline(api_live=True, discovery=discovery2, ports=ports2).run()
        self.assertEqual(self.query("SELECT status FROM recon_runs WHERE id=?", run2)[0][0], "completed")

        # api.example.com: NXDOMAIN -> resolves recorded.
        api_dns = self.query("SELECT status, changed_at FROM dns_records d JOIN hosts h ON h.id=d.host_id "
                             "WHERE h.hostname='api.example.com'")[0]
        self.assertEqual(api_dns[0], "resolves")
        self.assertIsNotNone(api_dns[1])

        # JS changed and introduced the internal endpoint + source map.
        js_findings = {r[0] for r in self.query("SELECT value FROM js_findings")}
        self.assertTrue(any("/api/internal/export" in v for v in js_findings))
        self.assertTrue(any("/api/internal/keys" in v for v in js_findings), "source map content analyzed")
        self.assertTrue(any(r[0] for r in self.query("SELECT changed_at FROM javascript_assets WHERE changed_at IS NOT NULL")))

        # OpenAPI endpoints ingested for api host.
        api_eps = self.query("SELECT COUNT(*) FROM endpoints WHERE host='api.example.com' AND source LIKE '%openapi%'")[0][0]
        self.assertGreaterEqual(api_eps, 25)
        # Sensitive parameter 'role' captured.
        self.assertTrue(self.query("SELECT 1 FROM parameters WHERE name='role'"))

        # New ports recorded.
        ports = {(r[0], r[1]) for r in self.query("SELECT host, port FROM services WHERE status='open'")}
        self.assertIn(("api.example.com", self.server.port), ports)
        self.assertIn(("admin.example.com", 8443), ports)

        # ---- Review queue: structural changes outrank the noisy page. ----
        queue = self.query("SELECT asset, review_priority, reason FROM review_items ORDER BY review_priority DESC")
        self.assertTrue(queue)
        prio = {r[0]: r[1] for r in queue}
        # The revived API host (new DNS + port + OpenAPI + internal JS endpoint) ranks highest.
        self.assertEqual(max(prio, key=prio.get), "api.example.com")
        # admin (404 -> 200 + new web port) and the apex (changed JS with an internal endpoint)
        # are high-value and rank well above the noisy news page.
        self.assertGreaterEqual(prio["admin.example.com"], 80)
        self.assertGreaterEqual(prio["example.com"], 90)
        self.assertGreater(prio["admin.example.com"], prio.get("news.example.com", 0))
        self.assertGreater(prio["example.com"], prio.get("news.example.com", 0))
        # The plain www page only has a low-value favicon change, well below the structural finds.
        self.assertLess(prio.get("www.example.com", 0), 50)
        self.assertGreater(prio["admin.example.com"], prio.get("www.example.com", 0))
        # Dangling/secret language stays review-only (no vulnerability claims).
        for _, _, reason in queue:
            self.assertNotIn("vulnerable", reason.lower())

    async def test_interrupted_run_is_marked_and_resumable(self) -> None:
        pipeline = self.make_pipeline(api_live=True, discovery=SCOPE_HOSTS, ports=[])

        # Cancel during the DNS stage to simulate Ctrl+C mid-pipeline.
        real_dns = pipeline._stage_dns

        async def cancel_during_dns():
            raise asyncio.CancelledError()
        pipeline._stage_dns = cancel_during_dns

        with self.assertRaises(asyncio.CancelledError):
            await pipeline.run()
        # Run recorded as interrupted; dns stage recorded as failed; discovery completed.
        self.assertEqual(self.query("SELECT status FROM recon_runs")[0][0], "interrupted")
        stages = {r[0]: r[1] for r in self.query("SELECT stage, status FROM recon_stages")}
        self.assertEqual(stages.get("discovery"), StageStatus.COMPLETED.value)
        self.assertEqual(stages.get("dns"), StageStatus.FAILED.value)
        self.assertNotIn("correlation", stages)

        # Resuming completes the run and re-runs dns onward without redoing discovery.
        resumed = await self.make_pipeline(api_live=True, discovery=SCOPE_HOSTS, ports=[]).run(resume=True)
        self.assertEqual(self.query("SELECT status FROM recon_runs WHERE id=?", resumed)[0][0], "completed")
        final = {r[0]: r[1] for r in self.query("SELECT stage, status FROM recon_stages WHERE run_id=?", resumed)}
        self.assertEqual(final.get("correlation"), StageStatus.COMPLETED.value)

    async def test_resume_skips_completed_stages(self) -> None:
        pipeline = self.make_pipeline(api_live=True, discovery=SCOPE_HOSTS, ports=[])
        run_id = await pipeline.run()
        # Reopen the DB and mark the run unfinished with correlation failed, to force a resume.
        db = Database(self.dir / "recon.db"); db.open()
        store = ReconStore(db)
        with db.transaction():
            db.conn.execute("UPDATE recon_runs SET status='failed' WHERE id=?", (run_id,))
            store.set_stage(run_id, "correlation", StageStatus.FAILED, "2026-01-01T00:00:00Z")
        db.close()

        resumed = await self.make_pipeline(api_live=True, discovery=SCOPE_HOSTS, ports=[]).run(resume=True)
        self.assertEqual(resumed, run_id, "resume should continue the same run")
        self.assertEqual(self.query("SELECT status FROM recon_runs WHERE id=?", run_id)[0][0], "completed")


if __name__ == "__main__":
    unittest.main()
