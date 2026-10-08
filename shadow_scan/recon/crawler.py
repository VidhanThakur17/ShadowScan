"""Bounded, scope-respecting recon crawler.

Designed for recon, not spidering: breadth-first with hard caps on depth,
per-host URLs and total URLs. It performs only safe GET navigation, never
submits forms, never follows dangerous action URLs (logout/delete/…), and
scope-checks every hop *before* fetching. It reuses :meth:`HttpProber.fetch`
rather than opening its own HTTP stack.

Pages are streamed via an async generator and processed one at a time, so the
crawler never holds all bodies in memory. Only a bounded HTML slice is passed
on for technology/title/link extraction.
"""

from __future__ import annotations

import logging
from collections import deque
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import AsyncIterator

from ..http_probe import FetchResult, HttpProber
from .scope import ScopeEngine
from .urls import is_dangerous_path, looks_like_js, normalize_url

logger = logging.getLogger(__name__)

_HTML_SLICE = 300 * 1024


@dataclass(slots=True)
class CrawlConfig:
    max_depth: int = 2
    max_urls_per_host: int = 200
    max_total_urls: int = 1000
    max_response_bytes: int = 2 * 1024 * 1024


@dataclass(slots=True)
class CrawlPage:
    url: str
    final_url: str
    status_code: int | None
    content_type: str | None
    html: str                       # bounded slice; empty for non-HTML
    links: list[str] = field(default_factory=list)
    js_urls: list[str] = field(default_factory=list)
    link_tags: list[tuple[str, str]] = field(default_factory=list)  # (rel, href) for <link>
    set_cookie: str | None = None
    headers: dict[str, str] = field(default_factory=dict)


class _LinkExtractor(HTMLParser):
    """Collects navigable links and script/link hrefs. Ignores forms/actions."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.hrefs: list[str] = []
        self.scripts: list[str] = []
        self.link_tags: list[tuple[str, str]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "a" and a.get("href"):
            self.hrefs.append(a["href"])
        elif tag == "script" and a.get("src"):
            self.scripts.append(a["src"])
        elif tag == "link" and a.get("href"):
            self.link_tags.append((a.get("rel", "").lower(), a["href"]))
        # <form> deliberately ignored: recon never submits or follows form actions.


def extract_links(html: str) -> tuple[list[str], list[str], list[tuple[str, str]]]:
    parser = _LinkExtractor()
    try:
        parser.feed(html)
    except Exception:  # malformed HTML must never crash a crawl
        pass
    return parser.hrefs, parser.scripts, parser.link_tags


def _is_html(content_type: str | None) -> bool:
    return bool(content_type) and "html" in content_type.lower()


class Crawler:
    def __init__(self, prober: HttpProber, scope: ScopeEngine, config: CrawlConfig | None = None) -> None:
        self._prober = prober
        self._scope = scope
        self._config = config or CrawlConfig()

    async def crawl(self, seeds: list[str]) -> AsyncIterator[CrawlPage]:
        """Yield crawled pages breadth-first, within all configured bounds."""
        cfg = self._config
        visited: set[str] = set()
        per_host: dict[str, int] = {}
        frontier: deque[tuple[str, int]] = deque()
        for seed in seeds:
            norm = normalize_url(seed)
            if norm and norm not in visited:
                visited.add(norm)
                frontier.append((norm, 0))

        fetched = 0
        while frontier and fetched < cfg.max_total_urls:
            url, depth = frontier.popleft()
            if not self._scope.may_probe_url(url):
                continue
            if is_dangerous_path(url):
                logger.debug("Skipping dangerous-action URL (not fetched): %s", url)
                continue
            host = _host(url)
            if per_host.get(host, 0) >= cfg.max_urls_per_host:
                continue
            per_host[host] = per_host.get(host, 0) + 1
            fetched += 1

            result = await self._prober.fetch(url, max_bytes=cfg.max_response_bytes)
            page = self._to_page(url, result)
            yield page

            if depth >= cfg.max_depth:
                continue
            for link in (*page.links, *page.js_urls):
                target = normalize_url(link, base=page.final_url)
                if not target or target in visited:
                    continue
                if not self._scope.may_probe_url(target):
                    continue
                if is_dangerous_path(target):
                    continue
                visited.add(target)
                if len(visited) <= cfg.max_total_urls * 4:   # bound frontier growth
                    frontier.append((target, depth + 1))

    def _to_page(self, url: str, result: FetchResult) -> CrawlPage:
        is_html = _is_html(result.content_type)
        html = result.text(_HTML_SLICE) if is_html else ""
        links, scripts, link_tags = extract_links(html) if is_html else ([], [], [])
        js_urls = []
        for src in scripts:
            resolved = normalize_url(src, base=result.final_url or url)
            if resolved and (looks_like_js(resolved) or looks_like_js(src)):
                js_urls.append(resolved)
        return CrawlPage(
            url=url,
            final_url=result.final_url or url,
            status_code=result.status_code,
            content_type=result.content_type,
            html=html,
            links=links,
            js_urls=js_urls,
            link_tags=link_tags,
            set_cookie=result.set_cookie,
            headers=result.headers,
        )


def _host(url: str) -> str:
    from .urls import url_host
    return url_host(url) or ""
