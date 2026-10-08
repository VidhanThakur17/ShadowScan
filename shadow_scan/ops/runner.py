"""Unified production run command.

Orchestrates the existing recon and security-analysis pipelines (never
reimplements them), then layers the operational concerns: run lock, preflight,
incremental/lifecycle bookkeeping, regression detection, notifications, run
summary and reporting. Honors the program's ``enabled_stages`` and ``global_mode``
(more restrictive always wins), preserves scope and policy enforcement, resumes
via the existing pipeline resumability, and shuts down gracefully.
"""

from __future__ import annotations

import asyncio
import logging
import os
import socket
from dataclasses import dataclass, field
from typing import Any

from ..config import ScanConfig
from ..database import Database
from ..recon.crawler import CrawlConfig
from ..recon.pipeline import ReconComponents, ReconConfig, ReconPipeline
from ..recon.scope import ScopeEngine
from ..secanalysis.ai import AIConfig
from ..secanalysis.cli import _load_endpoints_from_db
from ..secanalysis.pipeline import SecurityComponents, SecurityConfig, SecurityPipeline
from ..secanalysis.models import TestingPolicy
from ..utils import utc_now_iso
from .lifecycle import LifecycleManager, REGRESSION_PRIORITY
from .lock import LockError, RunLock
from .notify import Event, EventType, NotificationConfig, Notifier, build_providers
from .opsdb import OpsStore
from .preflight import preflight
from .report import RunReport, write_report
from .workspace import ProgramConfig, Workspace

logger = logging.getLogger(__name__)

_RECON_STAGES = {"discovery", "dns", "monitor", "services", "urls", "crawl", "javascript", "enrichment", "correlation"}
_SECURITY_STAGES = {"security_analysis", "validation", "ai_analysis"}


@dataclass(slots=True)
class RunnerComponents:
    aiohttp_resolver: object | None = None
    ai_provider: object | None = None
    recon_discovery_adapters: tuple = ()
    recon_url_adapters: tuple = ()
    recon_port_adapters: tuple = ()
    recon_resolver: object | None = None
    nuclei_adapter: object | None = None
    console_sink: Any = None
    webhook_opener: Any = None


@dataclass(slots=True)
class RunResult:
    run_id: int
    status: str
    summary: dict[str, Any]
    top_items: list[dict[str, Any]] = field(default_factory=list)
    notifications_sent: int = 0
    regressions: list[str] = field(default_factory=list)
    resolved: list[str] = field(default_factory=list)
    report_paths: list[str] = field(default_factory=list)


class UnifiedRunner:
    def __init__(self, workspace: Workspace, config: ProgramConfig,
                 components: RunnerComponents | None = None, *, force_lock: bool = False,
                 resume: bool = False, verify_tls: bool = True) -> None:
        self._ws = workspace
        self._config = config
        self._components = components or RunnerComponents()
        self._force_lock = force_lock
        self._resume = resume
        self._verify_tls = verify_tls
        self._ws.ensure_runtime()
        self._db = Database(workspace.db_path)
        self._store = OpsStore(self._db)

    def _enabled(self, stage: str) -> bool:
        return stage in self._config.enabled_stages

    async def run(self) -> RunResult:
        lock = RunLock(self._ws.lock_path, force=self._force_lock)
        try:
            lock.acquire()
        except LockError as exc:
            logger.error("%s", exc)
            raise
        status = "completed"
        run_id = -1
        summary: dict[str, Any] = {}
        regressions: list[str] = []
        resolved: list[str] = []
        self._db.open()
        try:
            now = utc_now_iso()
            self._store.ensure_schema(now)
            run_id = self._begin_run(now)
            notifier = self._make_notifier()

            # Preflight (no target interaction).
            if self._enabled("preflight"):
                with self._db.transaction():
                    pf = preflight(self._ws.db_path, program_config_ok=True,
                                   ai_enabled=self._config.raw.get("ai", {}).get("enabled", False),
                                   output_dirs=[self._ws.reports_dir, self._ws.exports_dir],
                                   store=self._store, now=now)
                if not pf.ok:
                    raise RuntimeError("preflight failed: " + "; ".join(
                        r.detail for r in pf.results if r.required and not r.ok))
                if pf.degraded:
                    logger.info("Degraded mode (optional components unavailable): %s", ", ".join(pf.degraded))

            try:
                if any(self._enabled(s) for s in _RECON_STAGES):
                    await self._run_recon()
                if any(self._enabled(s) for s in _SECURITY_STAGES):
                    await self._run_security()
                regressions, resolved = self._post_process(notifier, now)
                summary = self._build_summary(resolved, regressions)
                self._emit_run_notifications(notifier, summary, now, regressions)
                if self._enabled("reporting"):
                    report = RunReport(self._config.program_id, now, summary, summary.pop("_top_items", []))
                    self._write_reports(report)
                    result_reports = self._report_paths
                else:
                    result_reports = []
            except asyncio.CancelledError:
                status = "interrupted"
                logger.warning("Run interrupted; state preserved and resumable")
                try:
                    with self._db.transaction():
                        self._store.finish_run(run_id, utc_now_iso(), status, summary)
                except Exception:
                    pass
                raise
            except Exception:
                logger.exception("Run failed")
                status = "failed"
            with self._db.transaction():
                self._store.finish_run(run_id, utc_now_iso(), status, summary)
            return RunResult(run_id, status, summary, summary.get("_top_items_list", []),
                             notifications_sent=notifier.sent, regressions=regressions,
                             resolved=resolved, report_paths=getattr(self, "_report_paths", []))
        finally:
            self._db.close()
            lock.release()

    # -- run bookkeeping -------------------------------------------------------------

    def _begin_run(self, now: str) -> int:
        with self._db.transaction():
            prior = self._store.latest_unfinished_run(self._config.program_id) if self._resume else None
            if prior is not None:
                return int(prior["id"])
            return self._store.start_run(self._config.program_id, now, os.getpid(), socket.gethostname())

    def _scope(self) -> ScopeEngine:
        lines = list(self._config.scope_roots) + [f"!{h}" for h in self._config.excluded_hosts]
        return ScopeEngine.parse(lines)

    def _scan_config(self) -> ScanConfig:
        prof = self._config.profile
        return ScanConfig(database_path=self._ws.db_path, concurrency=prof.active_concurrency,
                          request_timeout=10.0, total_timeout=30.0, verify_tls=self._verify_tls)

    # -- stage groups (reuse existing pipelines) -------------------------------------

    async def _run_recon(self) -> None:
        c = self._components
        config = ReconConfig(
            scope=self._scope(), scan_config=self._scan_config(),
            crawl=CrawlConfig(max_depth=2, max_total_urls=1000),
            root_domains=tuple(sorted(self._scope().in_scope_hosts)),
            enable_services=self._enabled("services"), enable_urls=self._enabled("urls"),
            enable_crawl=self._enabled("crawl"), enable_javascript=self._enabled("javascript"),
        )
        components = ReconComponents(
            resolver=c.recon_resolver, aiohttp_resolver=c.aiohttp_resolver,
            discovery_adapters=c.recon_discovery_adapters, url_adapters=c.recon_url_adapters,
            port_adapters=c.recon_port_adapters, use_real_tools=not bool(c.recon_discovery_adapters),
        )
        await ReconPipeline(config, components).run(resume=self._resume)

    async def _run_security(self) -> None:
        c = self._components
        # Timestamp window to identify findings OBSERVED this run (the findings
        # table is cumulative). Anything with last_seen >= this was seen now.
        self._security_start = utc_now_iso()
        scope = self._scope()
        endpoints = [e for e in _load_endpoints_from_db(self._ws.db_path, "https", scope)
                     if scope.classify_host(e.host).value == "in_scope"]
        if not endpoints:
            logger.info("No in-scope endpoints for security analysis")
            return
        prof = self._config.profile
        config = SecurityConfig(
            scope=scope, scan_config=self._scan_config(), program=prof,
            ai=AIConfig(enabled=self._enabled("ai_analysis")),
            enable_active=prof.global_mode is TestingPolicy.SAFE_ACTIVE,
            enable_ai=self._enabled("ai_analysis"),
            auth_contexts=tuple(prof.auth_profiles.keys()) if self._enabled("validation") else (),
        )
        comps = SecurityComponents(ai_provider=c.ai_provider, nuclei_adapter=c.nuclei_adapter,
                                   aiohttp_resolver=c.aiohttp_resolver)
        await SecurityPipeline(config, endpoints, comps).run(resume=self._resume)

    # -- post-processing: lifecycle, regression, notifications -----------------------

    def _security_findings(self) -> list[dict[str, Any]]:
        if not _table(self._db, "security_findings"):
            return []
        rows = self._db.conn.execute(
            "SELECT dedup_key, asset, endpoint, category, title, review_priority, validation_state, last_seen "
            "FROM security_findings").fetchall()
        return [dict(zip(("dedup_key", "asset", "endpoint", "category", "title", "priority",
                          "validation_state", "last_seen"), r)) for r in rows]

    def _post_process(self, notifier: Notifier, now: str) -> tuple[list[str], list[str]]:
        security_start = getattr(self, "_security_start", None)
        if security_start is None:
            return [], []   # security did not run this invocation; don't touch lifecycle
        mgr = LifecycleManager(self._store, self._config.program_id)
        all_findings = self._security_findings()
        # Only findings observed THIS run (cumulative table; filter by last_seen window).
        findings = [f for f in all_findings if (f["last_seen"] or "") >= security_start]
        present = {f["dedup_key"] for f in findings}
        regressions: list[str] = []
        with self._db.transaction():
            for f in findings:
                result = mgr.observe(f["dedup_key"], now)
                if result.is_regression:
                    regressions.append(f["dedup_key"])
                    notifier.emit(Event(EventType.FINDING_REGRESSED, self._config.program_id,
                                        f"Regression: {f['title']}", priority=REGRESSION_PRIORITY,
                                        category=f["category"], asset=f["asset"],
                                        dedup_key=f"regress:{f['dedup_key']}:{now}"), now)
            # Continuous fix detection: confirmed/reported findings absent now are resolved.
            resolved = mgr.mark_resolved_if_absent(present, now)
        # New high-priority findings / authz reviews -> notifications.
        with self._db.transaction():
            for f in findings:
                if f["priority"] >= self._config.notify_min_priority:
                    etype = (EventType.AUTHORIZATION_REVIEW_REQUIRED
                             if f["category"] in ("authorization", "api_authorization")
                             else EventType.NEW_VALIDATED_FINDING
                             if f["validation_state"] == "validated_non_destructively"
                             else EventType.NEW_HIGH_PRIORITY_REVIEW_ITEM)
                    notifier.emit(Event(etype, self._config.program_id, f["title"], priority=f["priority"],
                                        category=f["category"], asset=f["asset"],
                                        dedup_key=f"finding:{f['dedup_key']}"), now)
        return regressions, resolved

    # -- summary & reports -----------------------------------------------------------

    def _count(self, sql: str, *params) -> int:
        try:
            return int(self._db.conn.execute(sql, params).fetchone()[0])
        except Exception:
            return 0

    def _build_summary(self, resolved: list[str], regressions: list[str]) -> dict[str, Any]:
        findings = self._security_findings()
        top = sorted(findings, key=lambda f: f["priority"], reverse=True)[:5]
        top_items = [{"priority": f["priority"], "title": f["title"], "asset": f["asset"]} for f in top]
        summary = {
            "hosts_known": self._count("SELECT COUNT(*) FROM hosts") if _table(self._db, "hosts") else 0,
            "hosts_resolving": self._count("SELECT COUNT(*) FROM dns_records WHERE status='resolves'")
                               if _table(self._db, "dns_records") else 0,
            "urls": self._count("SELECT COUNT(*) FROM urls") if _table(self._db, "urls") else 0,
            "js_assets": self._count("SELECT COUNT(*) FROM javascript_assets") if _table(self._db, "javascript_assets") else 0,
            "endpoints": self._count("SELECT COUNT(*) FROM endpoints") if _table(self._db, "endpoints") else 0,
            "security_findings": len(findings),
            "manual_review_required": sum(1 for f in findings if f["validation_state"] == "manual_validation_required"),
            "validated_non_destructively": sum(1 for f in findings if f["validation_state"] == "validated_non_destructively"),
            "regressions": len(regressions),
            "resolved_this_run": len(resolved),
            "_top_items": top_items,
            "_top_items_list": top_items,
        }
        return summary

    def _make_notifier(self) -> Notifier:
        providers = build_providers(
            self._config.notify_providers, file_path=self._ws.logs_dir / "notifications.jsonl",
            webhook_url=os.environ.get("SHADOWSCAN_WEBHOOK_URL"),
            console_sink=self._components.console_sink, webhook_opener=self._components.webhook_opener)
        cfg = NotificationConfig(min_priority=self._config.notify_min_priority,
                                 categories=self._config.notify_categories)
        return Notifier(providers, cfg, self._store, self._config.program_id)

    def _emit_run_notifications(self, notifier: Notifier, summary: dict, now: str, regressions: list[str]) -> None:
        with self._db.transaction():
            notifier.emit(Event(EventType.RUN_COMPLETED, self._config.program_id,
                                f"Run completed: {summary.get('security_findings', 0)} findings, "
                                f"{len(regressions)} regressions", priority=0,
                                dedup_key=f"run_completed:{now}"), now)

    def _write_reports(self, report: RunReport) -> None:
        self._report_paths = []
        stamp = report.run_timestamp.replace(":", "").replace("-", "")[:15]
        for fmt in self._config.report_formats:
            if fmt == "json":
                path = self._ws.reports_dir / f"run-{stamp}.json"
                write_report(path, report.to_json())
            elif fmt in ("markdown", "md"):
                path = self._ws.reports_dir / f"run-{stamp}.md"
                write_report(path, report.to_markdown())
            else:
                continue
            self._report_paths.append(str(path))


def _table(db: Database, name: str) -> bool:
    return db.conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone() is not None
