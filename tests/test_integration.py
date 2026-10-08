"""End-to-end tests against a local aiohttp server. No internet access required."""

import asyncio
import hashlib
import itertools
import json
import socket
import sqlite3
import tempfile
import unittest
from collections import Counter
from collections.abc import Callable
from contextlib import closing
from pathlib import Path

from aiohttp import web

from shadow_scan.config import ScanConfig
from shadow_scan.delta import build_report, write_report
from shadow_scan.http_probe import HttpProber
from shadow_scan.models import ChangeType, ErrorType, RunStatus
from shadow_scan.scanner import Scanner
from shadow_scan.utils import ScopePolicy, normalize_target, parse_targets

Page = tuple[int, bytes, str]


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class LocalServer:
    """A tiny mutable web app.

    ``pages[path]`` is ``(status, body, content_type)`` or a zero-argument
    callable returning one (for per-request dynamic content).
    """

    def __init__(self) -> None:
        self.pages: dict[str, Page | Callable[[], Page]] = {}
        self.hits: Counter[str] = Counter()
        self.cookies_seen: dict[str, list[dict[str, str]]] = {}
        self.port = 0
        self._runner: web.AppRunner | None = None

    async def _handle(self, request: web.Request) -> web.StreamResponse:
        path = request.path
        self.hits[path] += 1
        self.cookies_seen.setdefault(path, []).append(dict(request.cookies))
        if path == "/loop":
            raise web.HTTPFound("/loop")
        if path.startswith("/chain/"):
            raise web.HTTPFound(f"/chain/{int(path.rsplit('/', 1)[1]) + 1}")
        if path == "/redirect-in":
            raise web.HTTPFound("/page")
        if path == "/redirect-out":
            # Same server, different hostname -> outside the supplied scope.
            raise web.HTTPFound(f"http://localhost:{self.port}/secret")
        if path == "/cookie-gate":
            # Sets a cookie and redirects to itself; only completes when the cookie is replayed.
            if request.cookies.get("gate") == "passed":
                return web.Response(text="<html><title>Through the gate</title></html>", content_type="text/html")
            response = web.HTTPFound("/cookie-gate")
            response.set_cookie("gate", "passed")
            raise response
        if path.startswith("/login-"):
            # /login-a sets session=a for the whole host, then redirects to /home-a.
            name = path.removeprefix("/login-")
            response = web.HTTPFound(f"/home-{name}")
            response.set_cookie("session", name, path="/")
            raise response
        if path.startswith("/home-"):
            return web.Response(text="home", content_type="text/plain")
        page = self.pages.get(path, (404, b"not found", "text/plain"))
        status, body, content_type = page() if callable(page) else page
        return web.Response(status=status, body=body, content_type=content_type)

    async def start(self, port: int = 0) -> None:
        app = web.Application()
        app.router.add_route("GET", "/{tail:.*}", self._handle)
        self._runner = web.AppRunner(app, access_log=None)
        await self._runner.setup()
        site = web.TCPSite(self._runner, "127.0.0.1", port)
        await site.start()
        self.port = site._server.sockets[0].getsockname()[1]  # type: ignore[union-attr]

    async def stop(self) -> None:
        if self._runner is not None:
            await self._runner.cleanup()
            self._runner = None


def html(title: str, body: str = "") -> bytes:
    return f"<html><head><title>{title}</title></head><body>{body}</body></html>".encode()


def article(words: list[str], title: str = "Article") -> bytes:
    paragraphs = "".join(f"<p>{word} lorem ipsum dolor sit amet consectetur</p>\n" for word in words)
    return html(title, paragraphs)


WORDS = [f"word{i}" for i in range(300)]
PNG = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + bytes(range(256))


class IntegrationBase(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.server = LocalServer()
        await self.server.start()
        self.base = f"http://127.0.0.1:{self.server.port}"
        self.host = f"127.0.0.1:{self.server.port}"

    async def asyncTearDown(self) -> None:
        await self.server.stop()
        self.tmp.cleanup()

    def config(self, **overrides) -> ScanConfig:
        values = dict(
            database_path=self.dir / "test.db",
            output_path=self.dir / "deltas.json",
            concurrency=4,
            request_timeout=3,
            total_timeout=5,
            db_flush_interval=0.05,
        )
        values.update(overrides)
        return ScanConfig(**values)

    def query(self, sql: str, *params):
        with closing(sqlite3.connect(self.dir / "test.db")) as conn:
            conn.row_factory = sqlite3.Row
            return conn.execute(sql, params).fetchall()


class ProberTests(IntegrationBase):
    async def probe(self, raw: str, **config_overrides):
        target = normalize_target(raw)
        config = self.config(**config_overrides)
        async with HttpProber(config, ScopePolicy([target.hostname])) as prober:
            return await prober.probe(target)

    async def test_collects_response_metadata(self) -> None:
        body = html("Portal", "x" * 100)
        self.server.pages["/page"] = (200, body, "text/html")
        result = await self.probe(f"{self.base}/page")
        self.assertIsNone(result.error_type)
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.title, "Portal")
        self.assertEqual(result.scheme, "http")
        self.assertEqual(result.hostname, "127.0.0.1")
        self.assertEqual(result.downloaded_bytes, len(body))
        self.assertEqual(result.content_length_header, len(body))
        self.assertEqual(result.body_sha256, hashlib.sha256(body).hexdigest())
        self.assertEqual(result.fingerprints["raw_sha256"], result.body_sha256)
        self.assertIsNotNone(result.normalized_sha256)
        self.assertIsNotNone(result.similarity_sketch)
        self.assertTrue(result.http_reachable and result.observation_complete)
        self.assertTrue(result.content_type.startswith("text/html"))
        self.assertIsNotNone(result.server_header)
        self.assertGreater(result.response_time_ms, 0)

    async def test_in_scope_redirect_is_followed(self) -> None:
        self.server.pages["/page"] = (200, html("Landing"), "text/html")
        result = await self.probe(f"{self.base}/redirect-in")
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.redirect_count, 1)
        self.assertEqual(result.final_url, f"{self.base}/page")
        self.assertEqual(result.redirect_location, f"{self.base}/page")

    async def test_out_of_scope_redirect_is_never_requested(self) -> None:
        result = await self.probe(f"{self.base}/redirect-out")
        self.assertEqual(self.server.hits["/secret"], 0)
        self.assertEqual(result.status_code, 302)
        self.assertIsNone(result.error_type)
        self.assertEqual(result.redirect_location, f"http://localhost:{self.server.port}/secret")
        self.assertEqual(result.final_url, f"{self.base}/redirect-out")

    async def test_redirect_loop(self) -> None:
        result = await self.probe(f"{self.base}/loop")
        self.assertEqual(result.error_type, ErrorType.REDIRECT_LOOP)
        self.assertTrue(result.http_reachable)
        self.assertFalse(result.observation_complete)

    async def test_redirect_limit(self) -> None:
        result = await self.probe(f"{self.base}/chain/0", max_redirects=3)
        self.assertEqual(result.error_type, ErrorType.REDIRECT_LIMIT_EXCEEDED)
        self.assertEqual(result.redirect_count, 3)
        self.assertEqual(self.server.hits["/chain/4"], 0)

    async def test_body_read_is_bounded_and_marked_incomplete(self) -> None:
        body = b"A" * 300_000
        self.server.pages["/big"] = (200, body, "text/plain")
        result = await self.probe(f"{self.base}/big", max_response_bytes=1000)
        self.assertEqual(result.downloaded_bytes, 1000)
        self.assertTrue(result.body_truncated)
        self.assertEqual(result.error_type, ErrorType.RESPONSE_TOO_LARGE)
        self.assertEqual(result.body_sha256, hashlib.sha256(body[:1000]).hexdigest())
        self.assertIsNone(result.normalized_sha256)
        self.assertTrue(result.http_reachable)
        self.assertFalse(result.observation_complete)

    async def test_connection_refused(self) -> None:
        result = await self.probe(f"http://127.0.0.1:{free_port()}")
        self.assertEqual(result.error_type, ErrorType.CONNECTION_REFUSED)
        self.assertFalse(result.http_reachable)
        self.assertFalse(result.observation_complete)

    async def test_scheme_less_target_falls_back_to_http(self) -> None:
        # The server speaks plain HTTP, so the HTTPS attempt fails at the TLS layer.
        self.server.pages["/"] = (200, html("Home"), "text/html")
        result = await self.probe(self.host)
        self.assertIsNone(result.error_type)
        self.assertEqual(result.scheme, "http")
        self.assertTrue(result.fallback_used)
        self.assertEqual(result.title, "Home")

    async def test_explicit_https_does_not_fall_back(self) -> None:
        result = await self.probe(f"https://{self.host}")
        self.assertEqual(result.error_type, ErrorType.TLS_ERROR)
        self.assertFalse(result.fallback_used)
        self.assertNotIn("/", self.server.hits)

    async def test_fallback_disabled(self) -> None:
        result = await self.probe(self.host, http_fallback=False)
        self.assertFalse(result.http_reachable)
        self.assertEqual(result.url, f"https://{self.host}/")

    async def test_cookie_set_and_self_redirect_completes(self) -> None:
        result = await self.probe(f"{self.base}/cookie-gate")
        self.assertIsNone(result.error_type)
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.title, "Through the gate")
        self.assertEqual(result.redirect_count, 1)
        self.assertEqual(self.server.cookies_seen["/cookie-gate"], [{}, {"gate": "passed"}])

    async def test_cookies_are_isolated_between_targets_and_runs(self) -> None:
        targets = [normalize_target(f"{self.base}/login-{name}") for name in ("a", "b", "c")]
        targets.append(normalize_target(f"{self.base}/home-x"))
        config = self.config()
        scope = ScopePolicy([t.hostname for t in targets])
        async with HttpProber(config, scope) as prober:
            await asyncio.gather(*(prober.probe(t) for t in targets))   # concurrently, same session
            await prober.probe(targets[0])                              # same target again
        # Each chain carried only its own cookie...
        for name in ("a", "b", "c"):
            self.assertTrue(all(seen == {"session": name} for seen in self.server.cookies_seen[f"/home-{name}"]))
        # ...nothing leaked into an unrelated target on the same host...
        self.assertEqual(self.server.cookies_seen["/home-x"], [{}])
        # ...and nothing persisted into a later probe of the same target.
        self.assertTrue(all(seen == {} for seen in self.server.cookies_seen["/login-a"]))
        self.assertEqual(len(self.server.cookies_seen["/login-a"]), 2)

    async def test_cookie_redirect_off_scope_is_never_requested(self) -> None:
        self.server.pages.clear()
        result = await self.probe(f"{self.base}/redirect-out")
        self.assertEqual(self.server.hits["/secret"], 0)
        self.assertIsNone(result.error_type)


class ScannerTests(IntegrationBase):
    async def scan(self, lines: list[str], **config_overrides):
        targets, _ = parse_targets(lines)
        summary = await Scanner(self.config(**config_overrides), targets).run()
        self.assertEqual(summary.status, RunStatus.COMPLETED)
        return summary

    @staticmethod
    def by_target(summary) -> dict[str, list]:
        result: dict[str, list] = {}
        for change in summary.changes:
            result.setdefault(change.target, []).append(change)
        return result

    async def test_controlled_change_classification(self) -> None:
        tokens = itertools.count()
        pages = self.server.pages
        pages.update({
            "/admin": (404, b"nope", "text/plain"),
            "/forbidden": (403, html("Forbidden"), "text/html"),
            # A fresh CSRF token, nonce and request id on every single request.
            "/dynamic": lambda: (200, article(WORDS[:50], "Dyn").replace(
                b"<body>",
                f'<body data-request-id="req-{next(tokens):08d}"><meta name="csrf-token" content="tok{next(tokens)}">'
                f'<script nonce="n{next(tokens)}">init()</script>'.encode(),
            ), "text/html"),
            "/tiny-edit": (200, article(WORDS), "text/html"),
            "/minor-edit": (200, article(WORDS), "text/html"),
            "/rewrite": (200, article(WORDS), "text/html"),
            "/static": (200, article(WORDS, "Static"), "text/html"),
            "/logo.png": (200, PNG, "image/png"),
        })
        lines = [f"{self.base}{path}" for path in pages] + [f"{self.base}/admin"]

        first = await self.scan(lines)
        self.assertEqual(first.targets_processed, len(pages))
        self.assertEqual({c.change_type for c in first.changes}, {ChangeType.NEW_ASSET})

        second = await self.scan(lines)
        self.assertEqual(second.changes, [], "stable pages and token-only changes must produce zero deltas")
        self.assertEqual(second.raw_only_changes, 1, "the /dynamic raw hash changed but was suppressed")

        pages["/admin"] = (200, html("Admin console"), "text/html")
        pages["/forbidden"] = (200, html("Internal dashboard"), "text/html")
        pages["/tiny-edit"] = (200, article(WORDS[:150] + ["EDITED"] + WORDS[151:]), "text/html")
        pages["/minor-edit"] = (200, article(WORDS[:255] + [f"new{i}" for i in range(45)]), "text/html")
        pages["/rewrite"] = (200, article(WORDS[:30] + [f"other{i}" for i in range(270)], "Redesigned"), "text/html")
        pages["/logo.png"] = (200, PNG + b"\x01", "image/png")
        third = await self.scan(lines)
        changes = self.by_target(third)

        admin = changes[f"{self.host}/admin"]
        self.assertEqual([c.change_type for c in admin], [ChangeType.STATUS_CHANGED])
        self.assertTrue(admin[0].interesting)
        self.assertEqual(admin[0].review_priority, 85)

        forbidden = changes[f"{self.host}/forbidden"]
        self.assertEqual([(c.change_type, c.review_priority, c.interesting) for c in forbidden],
                         [(ChangeType.STATUS_CHANGED, 95, True)])
        self.assertEqual(forbidden[0].fields["context"]["title"], {"old": "Forbidden", "new": "Internal dashboard"})

        tiny = changes[f"{self.host}/tiny-edit"]
        self.assertEqual([(c.change_type, c.fields["magnitude"]) for c in tiny],
                         [(ChangeType.CONTENT_CHANGED_MINOR, "trivial")])
        minor = changes[f"{self.host}/minor-edit"]
        self.assertEqual([(c.change_type, c.fields["magnitude"]) for c in minor],
                         [(ChangeType.CONTENT_CHANGED_MINOR, "minor")])
        rewrite = {c.change_type: c for c in changes[f"{self.host}/rewrite"]}
        self.assertEqual(set(rewrite), {ChangeType.CONTENT_CHANGED_MAJOR, ChangeType.TITLE_CHANGED})
        self.assertEqual(rewrite[ChangeType.CONTENT_CHANGED_MAJOR].fields["magnitude"], "major")
        self.assertLess(rewrite[ChangeType.CONTENT_CHANGED_MAJOR].fields["similarity"], 0.8)
        logo = changes[f"{self.host}/logo.png"]
        self.assertEqual([(c.change_type, c.fields["magnitude"]) for c in logo],
                         [(ChangeType.CONTENT_CHANGED_MAJOR, "unmeasured")])
        self.assertNotIn(f"{self.host}/static", changes)
        self.assertNotIn(f"{self.host}/dynamic", changes)

        # deltas.json: current run only, sorted by review_priority, with interesting counts.
        output = self.dir / "deltas.json"
        write_report(output, build_report(third))
        report = json.loads(output.read_text(encoding="utf-8"))
        priorities = [c["review_priority"] for c in report["changes"]]
        self.assertEqual(priorities, sorted(priorities, reverse=True))
        self.assertEqual(report["changes"][0]["target"], f"{self.host}/forbidden")
        self.assertEqual(report["changes"][0]["old_status"], 403)
        self.assertEqual(report["changes"][0]["reason"], "Previously forbidden endpoint (403) now returns HTTP 200")
        self.assertEqual(report["interesting_changes"], 2)
        self.assertEqual(report["changes_found"], len(third.changes))

        # History metrics are maintained incrementally on the asset row.
        [row] = self.query(
            "SELECT observations_count, content_comparisons, content_change_count FROM assets WHERE target = ?",
            f"{self.host}/rewrite",
        )
        self.assertEqual(tuple(row), (3, 2, 1))
        [row] = self.query("SELECT observations_count, content_comparisons, content_change_count FROM assets WHERE target = ?",
                           f"{self.host}/dynamic")
        self.assertEqual(tuple(row), (3, 2, 0))
        self.assertEqual(self.query("PRAGMA journal_mode")[0][0], "wal")
        self.assertEqual(self.query("SELECT COUNT(*) FROM runs WHERE status = 'completed'")[0][0], 3)

    async def test_hostname_asset_identity(self) -> None:
        self.server.pages["/page"] = (200, html("P"), "text/html")
        await self.scan([f"{self.host}/page", f"http://{self.host}/page"])
        [asset] = self.query("SELECT id, requested_scheme, original_input FROM assets")
        self.assertEqual(asset["requested_scheme"], "http")
        [obs] = self.query("SELECT scheme, fallback_used FROM observations")
        self.assertEqual((obs["scheme"], obs["fallback_used"]), ("http", 0))

        # Same asset when the input switches to scheme-less: intent updated, history kept.
        second = await self.scan([f"{self.host}/page"])
        self.assertEqual(second.changes, [])
        [again] = self.query("SELECT id, requested_scheme, observations_count FROM assets")
        self.assertEqual((again["id"], again["requested_scheme"], again["observations_count"]), (asset["id"], None, 2))
        latest = self.query("SELECT scheme, fallback_used, url FROM observations ORDER BY id DESC LIMIT 1")[0]
        self.assertEqual((latest["scheme"], latest["fallback_used"]), ("http", 1))
        self.assertEqual(latest["url"], f"http://{self.host}/page")

    async def test_phase1_database_is_refused_with_instructions(self) -> None:
        with closing(sqlite3.connect(self.dir / "test.db")) as conn:
            conn.execute("PRAGMA user_version = 1")
        targets, _ = parse_targets([f"{self.base}/"])
        with self.assertLogs("shadow_scan.scanner", level="ERROR") as logs:
            summary = await Scanner(self.config(), targets).run()
        self.assertEqual(summary.status, RunStatus.FAILED)
        self.assertIn("schema v1", "\n".join(logs.output))
        self.assertEqual(self.server.hits.total(), 0, "nothing may be probed without a usable database")

    async def test_unchanged_content_moves_baseline_pointer_without_rewriting(self) -> None:
        self.server.pages["/a"] = (200, article(WORDS), "text/html")
        for _ in range(3):
            await self.scan([f"{self.base}/a"])
        [row] = self.query(
            "SELECT b.observation_id = a.last_complete_observation_id AS current, length(b.sketch) AS size "
            "FROM asset_content_baselines b JOIN assets a ON a.id = b.asset_id"
        )
        self.assertEqual(row["current"], 1)
        self.assertGreater(row["size"], 0)

    async def test_incomplete_observations_never_produce_content_changes(self) -> None:
        self.server.pages["/big"] = (200, b"A" * 5000, "text/plain")
        lines = [f"{self.base}/big"]
        await self.scan(lines, max_response_bytes=1000)
        self.server.pages["/big"] = (200, b"B" * 5000, "text/plain")
        second = await self.scan(lines, max_response_bytes=1000)
        self.assertEqual(second.changes, [])
        self.assertEqual(second.incomplete, 1)
        rows = self.query("SELECT http_reachable, observation_complete, error_type FROM observations")
        self.assertEqual({tuple(r) for r in rows}, {(1, 0, "response_too_large")})

    async def test_availability_and_error_transitions(self) -> None:
        flappy = LocalServer()
        flappy.pages["/"] = (200, html("Flappy"), "text/html")
        port = free_port()
        key = f"127.0.0.1:{port}"
        http_lines = [f"http://{key}"]
        https_lines = [f"https://{key}"]

        down = await self.scan(http_lines)
        self.assertEqual(down.unreachable, 1)
        self.assertEqual(down.error_counts, {"connection_refused": 1})

        await flappy.start(port)
        try:
            up = await self.scan(http_lines)
            # Explicit HTTPS against a plain-HTTP server: TLS failure, no fallback (still unreachable).
            tls = await self.scan(https_lines)
        finally:
            await flappy.stop()
        [change] = up.changes
        self.assertEqual((change.change_type, change.target), (ChangeType.AVAILABILITY_CHANGED, key))
        self.assertTrue(change.interesting)
        self.assertEqual(change.fields["old"]["state"], "unreachable")
        self.assertEqual(change.fields["new"]["status_code"], 200)
        self.assertEqual(change.fields["new"]["title"], "Flappy")

        [change] = tls.changes
        self.assertEqual(change.change_type, ChangeType.AVAILABILITY_CHANGED)
        self.assertEqual(change.fields["new"]["error_type"], "tls_error")
        self.assertFalse(change.interesting)

        # Still down, but the failure mode changed: tls_error -> connection_refused.
        refused = await self.scan(https_lines)
        [change] = refused.changes
        self.assertEqual(change.change_type, ChangeType.ERROR_CHANGED)
        self.assertEqual((change.fields["old_error"], change.fields["new_error"]), ("tls_error", "connection_refused"))

        quiet = await self.scan(https_lines)
        self.assertEqual(quiet.changes, [])

    async def test_many_targets_with_failures_complete(self) -> None:
        self.server.pages["/ok"] = (200, b"ok", "text/plain")
        dead = free_port()
        lines = [f"{self.base}/ok?n={i}" for i in range(60)] + [f"http://127.0.0.1:{dead}/x{i}" for i in range(5)]
        summary = await self.scan(lines, concurrency=10, db_batch_size=7)
        self.assertEqual(summary.targets_processed, 65)
        self.assertEqual(summary.reachable, 60)
        self.assertEqual(summary.unreachable, 5)

    async def test_large_text_is_normalized_off_loop_and_compared(self) -> None:
        big = article([f"w{i}" for i in range(4000)])   # > CPU_OFFLOAD_BYTES
        self.assertGreater(len(big), 64 * 1024)
        self.server.pages["/large"] = (200, big, "text/html")
        await self.scan([f"{self.base}/large"])
        self.server.pages["/large"] = (200, big.replace(b"w1999 ", b"CHANGED "), "text/html")
        summary = await self.scan([f"{self.base}/large"])
        [change] = summary.changes
        self.assertEqual((change.change_type, change.fields["magnitude"]), (ChangeType.CONTENT_CHANGED_MINOR, "trivial"))


if __name__ == "__main__":
    unittest.main()
