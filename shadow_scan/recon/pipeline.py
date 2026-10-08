"""Recon pipeline orchestration with resumable stages.

Stage order:

    discovery -> dns -> http -> services -> urls -> crawl -> javascript
    -> enrichment -> correlation

Design choices that satisfy the milestone's constraints:

* **Single writer.** All DB writes go through one :class:`Database` connection
  on this thread, in batched ``transaction()`` blocks. The HTTP stage reuses the
  monitoring :class:`~shadow_scan.scanner.Scanner`, whose own single writer
  thread writes the monitoring tables; recon reads those results afterwards
  over WAL. There is never more than one writer to any table.
* **Reuse, not duplication.** DNS feeds the existing monitor; crawl/JS/favicon
  fetches go through :meth:`HttpProber.fetch`.
* **Bounded everything.** Discovery/URL/port tools run behind adapters with
  timeouts; the crawler is capped; JS fetching is capped in count and size;
  network concurrency is semaphore-bounded.
* **Resumable.** Each stage's status lives in ``recon_stages``; a resumed run
  skips stages already ``completed``.

Scope is enforced before every active request: only IN_SCOPE hosts/URLs (or
UNKNOWN when ``probe_unknown`` is set on the scope engine) are ever fetched.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
from collections.abc import Sequence
from dataclasses import dataclass, field

from ..config import ScanConfig
from ..database import Database
from ..http_probe import HttpProber
from ..scanner import Scanner
from ..utils import ScopePolicy, normalize_target, utc_now_iso
from .correlation import AssetFacts, apply_noise_ranking, correlate, review_summary
from .crawler import CrawlConfig, Crawler
from .dns import Resolver, StdlibResolver, resolve_all
from .endpoints import endpoint_from_url, identity_string, is_interesting_param, make_endpoint
from .favicon import favicon_candidates, favicon_sha256
from .jsanalyze import analyze_js, analyze_source_map, source_map_references
from .models import (
    FindingType,
    ParamLocation,
    Parameter,
    ReconEvent,
    ScopeClass,
    Service,
    StageStatus,
    Technology,
    UrlRecord,
)
from .openapi import CONVENTIONAL_SPEC_PATHS, graphql_candidates_from_text, parse_openapi
from .recon_db import ReconStore
from .scope import ScopeEngine
from .tech import fingerprint
from .tools import available_adapters
from .tools.adapters import DISCOVERY_ADAPTERS, PORT_ADAPTERS, URL_ADAPTERS
from .urls import normalize_url, query_param_names, url_host

logger = logging.getLogger(__name__)

PORT_PROFILES = {
    "fast": "80,443,8080,8443,8000,8888",
    "web_extended": "80,81,443,591,2082,2087,3000,5000,7000,8000,8008,8080,8081,8443,8888,9000,9090,9200",
}
STAGES = ("discovery", "dns", "http", "services", "urls", "crawl", "javascript", "enrichment", "correlation")


@dataclass(slots=True)
class ReconConfig:
    scope: ScopeEngine
    scan_config: ScanConfig
    crawl: CrawlConfig = field(default_factory=CrawlConfig)
    seed_hosts: tuple[str, ...] = ()
    root_domains: tuple[str, ...] = ()
    dns_concurrency: int = 50
    fetch_concurrency: int = 20
    port_profile: str = "fast"
    custom_ports: str | None = None
    max_js_files: int = 300
    max_js_bytes: int = 3 * 1024 * 1024
    enable_discovery: bool = True
    enable_services: bool = True
    enable_urls: bool = True
    enable_crawl: bool = True
    enable_javascript: bool = True

    @property
    def ports(self) -> str:
        if self.port_profile == "custom" and self.custom_ports:
            return self.custom_ports
        return PORT_PROFILES.get(self.port_profile, PORT_PROFILES["fast"])


@dataclass(slots=True)
class ReconComponents:
    """Injectable collaborators; defaults use real tools/resolver. Tests inject fakes."""

    resolver: Resolver | None = None
    aiohttp_resolver: object | None = None   # custom DNS resolver for HTTP (offline tests)
    discovery_adapters: Sequence = ()
    url_adapters: Sequence = ()
    port_adapters: Sequence = ()
    use_real_tools: bool = True


class ReconPipeline:
    def __init__(self, config: ReconConfig, components: ReconComponents | None = None) -> None:
        config.scan_config.validate()
        self._config = config
        self._components = components or ReconComponents()
        self._db = Database(config.scan_config.database_path)
        self._store = ReconStore(self._db)
        self._facts: dict[str, AssetFacts] = {}
        self._run_id: int | None = None
        self._resolver = self._components.resolver or StdlibResolver()

    # -- fact accumulation -----------------------------------------------------------

    def _fact(self, host: str) -> AssetFacts:
        fact = self._facts.get(host)
        if fact is None:
            fact = AssetFacts(asset=host)
            self._facts[host] = fact
        return fact

    def _record_events(self, host: str, events: Sequence[ReconEvent]) -> None:
        self._fact(host).events.update(events)

    # -- lifecycle -------------------------------------------------------------------

    async def run(self, *, resume: bool = False) -> int:
        """Run (or resume) the pipeline. Returns the recon run id."""
        self._db.open()
        try:
            self._store.ensure_schema()
            now = utc_now_iso()
            if resume:
                self._run_id = self._store.latest_unfinished_run()
            if self._run_id is None:
                with self._db.transaction():
                    self._run_id = self._store.start_run(now, self._scope_hash())
                resume = False
            logger.info("Recon run #%d starting (%s)", self._run_id, "resume" if resume else "fresh")

            stage_fns = {
                "discovery": self._stage_discovery, "dns": self._stage_dns, "http": self._stage_http,
                "services": self._stage_services, "urls": self._stage_urls, "crawl": self._stage_crawl,
                "javascript": self._stage_javascript, "enrichment": self._stage_enrichment,
                "correlation": self._stage_correlation,
            }
            status = "completed"
            for stage in STAGES:
                if resume and self._store.stage_status(self._run_id, stage) is StageStatus.COMPLETED:
                    logger.info("Stage %s already completed; skipping", stage)
                    continue
                with self._db.transaction():
                    self._store.set_stage(self._run_id, stage, StageStatus.RUNNING, utc_now_iso())
                try:
                    await stage_fns[stage]()
                except asyncio.CancelledError:
                    # Record the interruption durably (stage + run) before propagating,
                    # so the run is resumable with --resume.
                    with self._db.transaction():
                        self._store.set_stage(self._run_id, stage, StageStatus.FAILED, utc_now_iso(), "interrupted")
                        self._store.finish_run(self._run_id, utc_now_iso(), "interrupted")
                    raise
                except Exception:
                    logger.exception("Stage %s failed", stage)
                    with self._db.transaction():
                        self._store.set_stage(self._run_id, stage, StageStatus.FAILED, utc_now_iso(), "error")
                    status = "failed"
                    break
                else:
                    with self._db.transaction():
                        self._store.set_stage(self._run_id, stage, StageStatus.COMPLETED, utc_now_iso())
            with self._db.transaction():
                self._store.finish_run(self._run_id, utc_now_iso(), status)
            logger.info("Recon run #%d %s", self._run_id, status)
            return self._run_id
        finally:
            self._db.close()

    def _scope_hash(self) -> str:
        blob = ",".join(sorted(self._config.scope.in_scope_hosts))
        return hashlib.sha256(blob.encode()).hexdigest()[:16]

    def _discovery_tools(self):
        c = self._components
        if c.discovery_adapters:
            return list(c.discovery_adapters)
        return available_adapters(DISCOVERY_ADAPTERS) if c.use_real_tools else []

    def _url_tools(self):
        c = self._components
        if c.url_adapters:
            return list(c.url_adapters)
        return available_adapters(URL_ADAPTERS) if c.use_real_tools else []

    def _port_tools(self):
        c = self._components
        if c.port_adapters:
            return list(c.port_adapters)
        return available_adapters(PORT_ADAPTERS) if c.use_real_tools else []

    # -- stage: discovery ------------------------------------------------------------

    async def _stage_discovery(self) -> None:
        now = utc_now_iso()
        # Seed hosts: exact scope hosts + explicit seeds, all in-scope by definition.
        seeds = set(self._config.scope.in_scope_hosts) | set(self._config.seed_hosts)
        discovered: dict[str, str] = {host: "scope" for host in seeds}

        roots = list(self._config.root_domains) or sorted(seeds)
        for tool in self._discovery_tools():
            try:
                found = await asyncio.to_thread(tool.run, roots)
            except Exception as exc:
                logger.warning("Discovery tool %s errored: %s", getattr(tool, "name", tool), exc)
                continue
            for host in found:
                normalized = self._normalize_host(host)
                if normalized and normalized not in discovered:
                    discovered[normalized] = tool.name

        with self._db.transaction():
            for host, source in discovered.items():
                scope_class = self._config.scope.classify_host(host)
                _, created = self._store.upsert_host(host, scope_class, source, now)
                if created and scope_class is ScopeClass.IN_SCOPE:
                    self._record_events(host, [ReconEvent.NEW_SUBDOMAIN])
        logger.info("Discovery: %d hosts (%d sources)", len(discovered), len(set(discovered.values())))

    @staticmethod
    def _normalize_host(raw: str) -> str | None:
        raw = raw.strip().lower().rstrip(".")
        if not raw or "/" in raw or " " in raw:
            return None
        try:
            return normalize_target(raw).hostname
        except Exception:
            return None

    # -- stage: dns ------------------------------------------------------------------

    async def _stage_dns(self) -> None:
        now = utc_now_iso()
        hosts = self._store.all_hosts(ScopeClass.IN_SCOPE)
        if not hosts:
            return
        records = await resolve_all(hosts, self._resolver, concurrency=self._config.dns_concurrency)
        with self._db.transaction():
            for record in records:
                host_id = self._store.host_id(record.hostname)
                if host_id is None:
                    continue
                events = self._store.record_dns(host_id, record, now)
                self._record_events(record.hostname, events)
        self._live_hosts = [r.hostname for r in records if r.resolves]
        logger.info("DNS: %d/%d hosts resolve", len(self._live_hosts), len(hosts))

    def _live_in_scope(self) -> list[str]:
        hosts = getattr(self, "_live_hosts", None)
        if hosts is not None:
            return hosts
        # On resume the in-memory list is gone; recompute from stored resolving records.
        rows = self._db.conn.execute(
            "SELECT h.hostname FROM hosts h JOIN dns_records d ON d.host_id = h.id "
            "WHERE d.status = 'resolves' AND h.scope_class = ?", (ScopeClass.IN_SCOPE.value,)
        ).fetchall()
        return [r[0] for r in rows]

    # -- stage: http (reuse monitoring Scanner) --------------------------------------

    async def _stage_http(self) -> None:
        hosts = self._live_in_scope()
        if not hosts:
            return
        targets = [normalize_target(self._config.scope.monitor_target(h)) for h in hosts]
        # Reuse the monitoring engine wholesale: it writes observations/changes itself.
        summary = await Scanner(self._config.scan_config, targets,
                                 http_resolver=self._components.aiohttp_resolver).run()
        logger.info("HTTP: monitored %d hosts, %d changes", summary.targets_processed, len(summary.changes))

    # -- stage: services -------------------------------------------------------------

    async def _stage_services(self) -> None:
        if not self._config.enable_services:
            return
        tools = self._port_tools()
        if not tools:
            logger.info("Services: no port scanner available; skipping")
            return
        hosts = self._live_in_scope()
        if not hosts:
            return
        now = utc_now_iso()
        open_by_host: dict[str, set[int]] = {}
        for tool in tools:
            try:
                results = await asyncio.to_thread(tool.run, hosts)
            except Exception as exc:
                logger.warning("Port tool %s errored: %s", getattr(tool, "name", tool), exc)
                continue
            for entry in results:
                host, _, port_s = entry.rpartition(":")
                if not host or not port_s.isdigit():
                    continue
                port = int(port_s)
                if self._config.scope.classify_service(host, port) is not ScopeClass.IN_SCOPE:
                    continue
                open_by_host.setdefault(host, set()).add(port)

        with self._db.transaction():
            for host, ports in open_by_host.items():
                new_ports: list[int] = []
                for port in sorted(ports):
                    events = self._store.record_service(
                        Service(host=host, port=port, service_guess=_guess_service(port), source="portscan"), now
                    )
                    if ReconEvent.NEW_OPEN_PORT in events:
                        new_ports.append(port)
                    self._record_events(host, events)
                self._store.mark_closed_ports(host, ports, now)
                self._fact(host).new_ports.extend(new_ports)
        logger.info("Services: %d hosts with open ports", len(open_by_host))

    # -- stage: urls -----------------------------------------------------------------

    async def _stage_urls(self) -> None:
        if not self._config.enable_urls:
            return
        tools = self._url_tools()
        if not tools:
            return
        now = utc_now_iso()
        roots = list(self._config.root_domains) or self._store.all_hosts(ScopeClass.IN_SCOPE)
        collected: set[str] = set()
        for tool in tools:
            try:
                results = await asyncio.to_thread(tool.run, roots)
            except Exception as exc:
                logger.warning("URL tool %s errored: %s", getattr(tool, "name", tool), exc)
                continue
            collected.update(results)
        with self._db.transaction():
            for raw in collected:
                self._store_url(raw, source="passive", now=now)
        logger.info("URLs: %d collected from passive sources", len(collected))

    def _store_url(self, raw: str, *, source: str, now: str, status_code: int | None = None) -> bool:
        normalized = normalize_url(raw)
        if not normalized:
            return False
        host = url_host(normalized) or ""
        scope_class = self._config.scope.classify_url(normalized)
        record = UrlRecord(
            url=normalized, host=host, path=_path_of(normalized),
            param_names=query_param_names(normalized), source=source,
            status_code=status_code, scope_class=scope_class,
        )
        is_new = self._store.record_url(record, now)
        # Feed query parameters into the parameter inventory (in-scope only).
        if scope_class is ScopeClass.IN_SCOPE:
            for name in record.param_names:
                self._record_parameter(host, name, ParamLocation.QUERY, source, now,
                                        endpoint=identity_string(endpoint_from_url(normalized) or make_endpoint(host, "/")))
        return is_new

    def _record_parameter(self, host: str, name: str, location: ParamLocation, source: str, now: str,
                          endpoint: str | None = None) -> None:
        is_new = self._store.record_parameter(
            Parameter(name=name, location=location, endpoint_identity=endpoint, source=source, confidence=0.7), now
        )
        if is_new and is_interesting_param(name):
            self._fact(host).new_parameters.append(name)
            self._record_events(host, [ReconEvent.NEW_PARAMETER])

    # -- stage: crawl ----------------------------------------------------------------

    async def _stage_crawl(self) -> None:
        if not self._config.enable_crawl:
            return
        hosts = self._live_in_scope()
        if not hosts:
            return
        self._js_urls: set[str] = set()
        seeds = [u for h in hosts for u in self._config.scope.probe_urls(h)]
        async with HttpProber(self._config.scan_config, ScopePolicy(hosts),
                              resolver=self._components.aiohttp_resolver) as prober:
            crawler = Crawler(prober, self._config.scope, self._config.crawl)
            now = utc_now_iso()
            async for page in crawler.crawl(seeds):
                with self._db.transaction():
                    self._process_page(page, now)
        logger.info("Crawl: collected %d JavaScript URLs", len(getattr(self, "_js_urls", set())))

    def _process_page(self, page, now: str) -> None:
        host = url_host(page.final_url) or ""
        self._store_url(page.url, source="crawl", now=now, status_code=page.status_code)
        # Endpoint inventory from the page itself and its links.
        self._store_endpoint(endpoint_from_url(page.final_url, method="GET", source="crawl", confidence=0.6), host, now)
        for link in page.links:
            target = normalize_url(link, base=page.final_url)
            if target and self._config.scope.classify_url(target) is ScopeClass.IN_SCOPE:
                self._store_url(target, source="html", now=now)
        for js in page.js_urls:
            if self._config.scope.classify_url(js) is ScopeClass.IN_SCOPE:
                self._js_urls.add(js)
        # Technology + favicon + graphql from the page body.
        for tech in fingerprint(headers=page.headers, html=page.html, set_cookie=page.set_cookie):
            self._record_events(host, self._store.record_technology(host, tech, now))
        if page.html and graphql_candidates_from_text(page.html):
            self._record_events(host, [ReconEvent.NEW_GRAPHQL])
        self._favicon_targets = getattr(self, "_favicon_targets", {})
        if host not in self._favicon_targets:
            candidates = favicon_candidates(page)
            if candidates:
                self._favicon_targets[host] = candidates[0]

    def _store_endpoint(self, endpoint, host: str, now: str) -> None:
        if endpoint is None:
            return
        identity = identity_string(endpoint)
        if self._store.record_endpoint(endpoint, identity, now):
            self._record_events(host, [ReconEvent.NEW_ENDPOINT])
            self._fact(host).new_endpoints.append(identity)

    # -- stage: javascript -----------------------------------------------------------

    async def _stage_javascript(self) -> None:
        if not self._config.enable_javascript:
            return
        # Defense-in-depth: re-check scope here even though js_urls were gated at collection.
        js_urls = sorted(u for u in getattr(self, "_js_urls", set()) if self._config.scope.may_probe_url(u))
        js_urls = js_urls[: self._config.max_js_files]
        if not js_urls:
            return
        semaphore = asyncio.Semaphore(self._config.fetch_concurrency)
        async with HttpProber(self._config.scan_config, ScopePolicy(self._live_in_scope()),
                              resolver=self._components.aiohttp_resolver) as prober:
            async def fetch(url: str):
                async with semaphore:
                    return url, await prober.fetch(url, max_bytes=self._config.max_js_bytes)

            results = await asyncio.gather(*(fetch(u) for u in js_urls))
            now = utc_now_iso()
            for url, result in results:
                if not result.ok or not result.body:
                    continue
                await self._process_js(prober, url, result, now)

    async def _process_js(self, prober: HttpProber, url: str, result, now: str) -> None:
        host = url_host(url) or ""
        body = result.text()
        raw_sha = hashlib.sha256(result.body).hexdigest()
        findings = analyze_js(body, source_url=url)
        smaps = source_map_references(findings)
        with self._db.transaction():
            js_id, events = self._store.record_js(
                url, host, raw_sha, raw_sha, len(result.body), smaps[0] if smaps else None, now
            )
            self._record_events(host, events)
            new_findings = self._store.record_js_findings(js_id, findings, now)
            self._apply_js_findings(host, new_findings, now)
        # Optionally fetch an in-scope source map under strict size limits.
        for smap in smaps[:1]:
            await self._fetch_source_map(prober, url, smap, host, now)

    def _apply_js_findings(self, host: str, findings, now: str) -> None:
        fact = self._fact(host)
        for f in findings:
            if f.finding_type in (FindingType.ENDPOINT_CANDIDATE, FindingType.ROUTE_CANDIDATE):
                path = f.value.split("?", 1)[0]
                if path.startswith("/"):
                    self._store_endpoint(make_endpoint(host, path, source="js", confidence=f.confidence), host, now)
                    self._record_events(host, [ReconEvent.NEW_JS_ENDPOINT])
                    fact.new_js_endpoints.append(f.value)
            elif f.finding_type is FindingType.PARAMETER_CANDIDATE:
                self._record_parameter(host, f.value, ParamLocation.UNKNOWN, "js", now)
                self._record_events(host, [ReconEvent.NEW_JS_PARAMETER])
            elif f.finding_type is FindingType.HOSTNAME_CANDIDATE:
                self._record_events(host, [ReconEvent.NEW_JS_HOSTNAME])
            elif f.finding_type is FindingType.SECRET_CANDIDATE:
                self._record_events(host, [ReconEvent.NEW_SECRET_CANDIDATE])
                fact.new_secret_count += 1
            elif f.finding_type is FindingType.SOURCE_MAP:
                self._record_events(host, [ReconEvent.NEW_SOURCE_MAP])
            elif f.finding_type is FindingType.GRAPHQL_CANDIDATE:
                self._record_events(host, [ReconEvent.NEW_GRAPHQL])

    async def _fetch_source_map(self, prober: HttpProber, js_url: str, ref: str, host: str, now: str) -> None:
        target = normalize_url(ref, base=js_url)
        if not target or not self._config.scope.may_probe_url(target):
            return
        result = await prober.fetch(target, max_bytes=self._config.max_js_bytes)
        if not result.ok or not result.body:
            return
        findings = analyze_source_map(result.text())
        if findings:
            with self._db.transaction():
                js_id, _ = self._store.record_js(target, host, hashlib.sha256(result.body).hexdigest(),
                                                 None, len(result.body), None, now)
                new = self._store.record_js_findings(js_id, findings, now)
                self._apply_js_findings(host, new, now)

    # -- stage: enrichment (conventional OpenAPI, favicons) --------------------------

    async def _stage_enrichment(self) -> None:
        hosts = self._live_in_scope()
        if not hosts:
            return
        async with HttpProber(self._config.scan_config, ScopePolicy(hosts),
                              resolver=self._components.aiohttp_resolver) as prober:
            await self._fetch_openapi(prober)
            await self._fetch_favicons(prober)

    async def _fetch_openapi(self, prober: HttpProber) -> None:
        now = utc_now_iso()
        for host in self._live_in_scope():
            bases = [u.rstrip("/") for u in self._config.scope.probe_urls(host)]
            for path in CONVENTIONAL_SPEC_PATHS:
                url = next((b + path for b in bases if self._config.scope.may_probe_url(b + path)), None)
                if url is None:
                    continue
                result = await prober.fetch(url, max_bytes=self._config.max_js_bytes)
                if not result.ok or result.status_code != 200 or not result.body:
                    continue
                spec = parse_openapi(result.text(), host, source="openapi")
                if spec is None:
                    continue
                self._store_openapi(host, spec, now)
                break  # one spec per host is enough for this milestone

    def _store_openapi(self, host: str, spec, now: str) -> None:
        with self._db.transaction():
            new_count = 0
            for endpoint in spec.endpoints:
                identity = identity_string(endpoint)
                if self._store.record_endpoint(endpoint, identity, now):
                    new_count += 1
            for param in spec.parameters:
                if self._store.record_parameter(param, now) and is_interesting_param(param.name):
                    self._fact(host).new_parameters.append(param.name)
            self._record_events(host, [ReconEvent.NEW_OPENAPI])
            fact = self._fact(host)
            fact.new_openapi_endpoint_count += new_count
            fact.new_endpoints.extend(identity_string(e) for e in spec.endpoints)
        logger.info("OpenAPI: %s exposed %d endpoints (%d new)", host, len(spec.endpoints), new_count)

    async def _fetch_favicons(self, prober: HttpProber) -> None:
        now = utc_now_iso()
        targets = getattr(self, "_favicon_targets", {})
        for host, url in targets.items():
            if not self._config.scope.may_probe_url(url):
                continue
            result = await prober.fetch(url, max_bytes=256 * 1024)
            if not result.ok or not result.body:
                continue
            sha = favicon_sha256(result.body)
            if sha:
                with self._db.transaction():
                    self._record_events(host, self._store.record_favicon(host, sha, now))

    # -- stage: correlation ----------------------------------------------------------

    async def _stage_correlation(self) -> None:
        now = utc_now_iso()
        # Ensure every live in-scope host is considered, so a monitoring-only
        # transition (e.g. 404 -> 200) still reaches correlation.
        for host in self._live_in_scope():
            self._fact(host)
        # Enrich facts with monitoring HTTP results and noise ratio.
        for host, fact in self._facts.items():
            status, title = self._store.latest_http(host)
            fact.http_status = status
            fact.title = title
            magnitude, priority = self._store.latest_content_change(host)
            fact.content_change_magnitude = magnitude
            fact.monitoring_priority = priority
            t_priority, _t_type, t_reason = self._store.latest_interesting_transition(host)
            fact.monitoring_transition_priority = t_priority
            fact.monitoring_transition_reason = t_reason
            fact.change_ratio = self._store.host_change_ratio(host)

        asset_signal_count = 0
        with self._db.transaction():
            for host, fact in self._facts.items():
                signals = apply_noise_ranking(fact, correlate(fact))
                if not signals:
                    continue
                asset_signal_count += 1
                for signal in signals:
                    self._store.add_signal(self._run_id, signal, now)
                priority, headline, reasons = review_summary(fact, signals)
                self._store.upsert_review_item(host, priority, headline, reasons, now)
        logger.info("Correlation: %d assets produced signals", asset_signal_count)


def _path_of(url: str) -> str:
    from .urls import url_path
    return url_path(url)


def _guess_service(port: int) -> str | None:
    return {
        80: "http", 443: "https", 8080: "http-alt", 8443: "https-alt", 8000: "http-alt",
        8888: "http-alt", 22: "ssh", 21: "ftp", 3306: "mysql", 5432: "postgresql",
        6379: "redis", 27017: "mongodb", 9200: "elasticsearch", 3000: "http-dev", 5000: "http-dev",
    }.get(port)
