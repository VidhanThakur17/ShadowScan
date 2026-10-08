"""Crawler tests against a local aiohttp server. No internet access."""

import unittest

from aiohttp import web

from shadow_scan.config import ScanConfig
from shadow_scan.http_probe import HttpProber
from shadow_scan.recon.crawler import CrawlConfig, Crawler, extract_links
from shadow_scan.recon.favicon import favicon_candidates, favicon_sha256
from shadow_scan.recon.scope import ScopeEngine
from shadow_scan.utils import ScopePolicy


class LinkExtractTests(unittest.TestCase):
    def test_extract_links_ignores_forms(self) -> None:
        html = (
            '<a href="/a">A</a><a href="https://evil.com/x">E</a>'
            '<script src="/app.js"></script><link rel="icon" href="/fav.ico">'
            '<form action="/delete"><input name="q"></form>'
        )
        hrefs, scripts, link_tags = extract_links(html)
        self.assertEqual(hrefs, ["/a", "https://evil.com/x"])
        self.assertEqual(scripts, ["/app.js"])
        self.assertEqual(link_tags, [("icon", "/fav.ico")])
        self.assertNotIn("/delete", hrefs)


class CrawlerTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.hits: list[str] = []
        app = web.Application()
        app.router.add_route("GET", "/{tail:.*}", self._handle)
        self.runner = web.AppRunner(app, access_log=None)
        await self.runner.setup()
        site = web.TCPSite(self.runner, "127.0.0.1", 0)
        await site.start()
        self.port = site._server.sockets[0].getsockname()[1]
        self.base = f"http://127.0.0.1:{self.port}"

    async def asyncTearDown(self) -> None:
        await self.runner.cleanup()

    async def _handle(self, request: web.Request) -> web.Response:
        self.hits.append(request.path)
        pages = {
            "/": '<a href="/a">a</a><a href="/b">b</a><a href="/account/logout">out</a>'
                 '<script src="/app.js"></script><a href="http://evil.com/x">evil</a>',
            "/a": '<a href="/a/deep">deep</a>',
            "/a/deep": '<a href="/a/deeper">deeper</a>',
            "/a/deeper": "<p>bottom</p>",
            "/b": "<p>b</p>",
            "/app.js": "console.log(1)",
            "/account/logout": "<p>should never be fetched</p>",
        }
        body = pages.get(request.path, "<p>404</p>")
        ctype = "application/javascript" if request.path.endswith(".js") else "text/html"
        return web.Response(text=body, content_type=ctype)

    def crawler(self, **cfg) -> Crawler:
        prober = self._prober
        scope = ScopeEngine.parse(["127.0.0.1", "@ports 80,443," + str(self.port)])
        return Crawler(prober, scope, CrawlConfig(**cfg))

    async def _run(self, **cfg) -> list:
        config = ScanConfig(concurrency=2, request_timeout=3, total_timeout=5)
        async with HttpProber(config, ScopePolicy(["127.0.0.1"])) as prober:
            self._prober = prober
            pages = [p async for p in self.crawler(**cfg).crawl([self.base + "/"])]
        return pages

    async def test_depth_limit(self) -> None:
        pages = await self._run(max_depth=1)
        paths = {p.url.replace(self.base, "") for p in pages}
        self.assertIn("/", paths)
        self.assertIn("/a", paths)
        self.assertNotIn("/a/deep", paths, "depth 1 must not reach depth-2 pages")

    async def test_deeper_depth_reaches_more(self) -> None:
        pages = await self._run(max_depth=3)
        paths = {p.url.replace(self.base, "") for p in pages}
        self.assertIn("/a/deep", paths)
        self.assertIn("/a/deeper", paths)

    async def test_total_url_limit(self) -> None:
        pages = await self._run(max_depth=5, max_total_urls=3)
        self.assertLessEqual(len(pages), 3)

    async def test_dangerous_url_never_fetched(self) -> None:
        await self._run(max_depth=2)
        self.assertNotIn("/account/logout", self.hits)

    async def test_offscope_never_fetched_and_js_collected(self) -> None:
        pages = await self._run(max_depth=2)
        self.assertFalse(any("evil.com" in h for h in self.hits))
        root = next(p for p in pages if p.url.endswith("/"))
        self.assertTrue(any(js.endswith("/app.js") for js in root.js_urls))


class FaviconTests(unittest.TestCase):
    def test_candidates_prefer_declared_then_default(self) -> None:
        from shadow_scan.recon.crawler import CrawlPage
        page = CrawlPage(url="https://e.com/", final_url="https://e.com/", status_code=200,
                         content_type="text/html", html="", link_tags=[("icon", "/static/fav.png")])
        cands = favicon_candidates(page)
        self.assertEqual(cands[0], "https://e.com/static/fav.png")
        self.assertIn("https://e.com/favicon.ico", cands)

    def test_hash_stable_and_empty(self) -> None:
        self.assertEqual(favicon_sha256(b"abc"), favicon_sha256(b"abc"))
        self.assertIsNone(favicon_sha256(b""))


if __name__ == "__main__":
    unittest.main()
