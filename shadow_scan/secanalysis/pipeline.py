"""Security-analysis orchestrator with resumable stages.

Stages: ``security_analysis -> validation -> correlation -> ai_analysis``.

Safety-critical flow, per endpoint:

1. The policy engine decides the testing policy and the decision is persisted.
2. Passive checks run on captured/stored evidence (no state change).
3. SAFE_ACTIVE checks run only when the decision is SAFE_ACTIVE *and* the
   program's global mode permits active work; every request goes through the
   budget governor + rate limiter.
4. REVIEW_REQUIRED endpoints get a manual-validation package, never an
   automated state-changing request.

Reuses :meth:`HttpProber.fetch` (no second HTTP stack), the recon inventory, and
the single-writer DB. A failed AI provider or active check never invalidates the
deterministic analysis or the recon run. Incremental: only endpoints whose
evidence changed are re-analyzed (future evidence-fingerprint hook; the orchestrator
already skips completed stages on resume).
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Sequence
from dataclasses import dataclass, field

from ..config import ScanConfig
from ..database import Database
from ..http_probe import HttpProber
from ..recon.scope import ScopeEngine
from ..utils import ScopePolicy, utc_now_iso
from .ai import AIAnalyzer, AIConfig, EvidenceBundle, MockProvider
from .budget import BudgetExceeded, RequestGovernor
from .checks import ACTIVE_CHECKS, PASSIVE_CHECKS
from .checks.base import CheckContext, FetchRecord
from .classify import ParamClass, classify_parameter, relevance_score
from .diffanalysis import compare_contexts, object_reference_candidates, observe
from .findings import deduplicate, excerpt, redact_headers
from .manualpkg import build_package
from .models import (
    CheckRequest,
    EndpointInfo,
    Finding,
    StageStatus,
    TestingPolicy,
    ValidationState,
)
from .policy import PolicyEngine
from .profiles import ProgramProfile, default_profile
from .sec_db import SecurityStore
from .seccorrelation import AssetSecurityFacts, correlate

logger = logging.getLogger(__name__)

STAGES = ("security_analysis", "validation", "correlation", "ai_analysis")


@dataclass(slots=True)
class SecurityConfig:
    scope: ScopeEngine
    scan_config: ScanConfig
    program: ProgramProfile = field(default_factory=default_profile)
    ai: AIConfig = field(default_factory=AIConfig)
    enable_active: bool = True
    enable_ai: bool = True
    auth_contexts: tuple[str, ...] = ()        # names of auth profiles to use for diff analysis


@dataclass(slots=True)
class SecurityComponents:
    ai_provider: object | None = None
    nuclei_adapter: object | None = None
    aiohttp_resolver: object | None = None


class SecurityPipeline:
    def __init__(self, config: SecurityConfig, endpoints: Sequence[EndpointInfo],
                 components: SecurityComponents | None = None) -> None:
        config.scan_config.validate()
        self._config = config
        self._endpoints = list(endpoints)
        self._components = components or SecurityComponents()
        self._db = Database(config.scan_config.database_path)
        self._store = SecurityStore(self._db)
        self._run_id: int | None = None
        prof = config.program
        self._policy = PolicyEngine(
            global_mode=prof.global_mode, allowed_methods=prof.allowed_methods,
            excluded_path_res=prof.excluded_path_res(), in_scope=True,
        )
        self._governor = RequestGovernor(
            max_requests_per_run=prof.max_requests_per_run,
            max_requests_per_endpoint=prof.max_requests_per_endpoint,
            requests_per_second_per_host=prof.requests_per_second_per_host,
            active_concurrency=prof.active_concurrency,
        )
        self._findings: list[Finding] = []
        self._finding_ids: dict[str, int] = {}
        self._prober: HttpProber | None = None

    async def run(self, *, resume: bool = False) -> int:
        self._db.open()
        try:
            # Recon schema may or may not exist; security schema is additive.
            self._store.ensure_schema()
            self._persist_auth_metadata()
            now = utc_now_iso()
            if resume:
                self._run_id = self._store.latest_unfinished_run()
            if self._run_id is None:
                with self._db.transaction():
                    self._run_id = self._store.start_run(now, self._config.program.name)
                resume = False
            logger.info("Security run #%d starting (%s)", self._run_id, "resume" if resume else "fresh")

            stage_fns = {
                "security_analysis": self._stage_security_analysis,
                "validation": self._stage_validation,
                "correlation": self._stage_correlation,
                "ai_analysis": self._stage_ai,
            }
            status = "completed"
            async with HttpProber(self._config.scan_config, ScopePolicy(self._scope_hosts()),
                                  resolver=self._components.aiohttp_resolver) as prober:
                self._prober = prober
                for stage in STAGES:
                    if resume and self._store.stage_status(self._run_id, stage) is StageStatus.COMPLETED:
                        continue
                    with self._db.transaction():
                        self._store.set_stage(self._run_id, stage, StageStatus.RUNNING, utc_now_iso())
                    try:
                        await stage_fns[stage]()
                    except asyncio.CancelledError:
                        with self._db.transaction():
                            self._store.set_stage(self._run_id, stage, StageStatus.FAILED, utc_now_iso(), "interrupted")
                            self._store.finish_run(self._run_id, utc_now_iso(), "interrupted")
                        raise
                    except Exception:
                        logger.exception("Security stage %s failed", stage)
                        with self._db.transaction():
                            self._store.set_stage(self._run_id, stage, StageStatus.FAILED, utc_now_iso(), "error")
                        # A failed stage (e.g. AI) must not abort the whole analysis run.
                        continue
                    with self._db.transaction():
                        self._store.set_stage(self._run_id, stage, StageStatus.COMPLETED, utc_now_iso())
            with self._db.transaction():
                self._store.finish_run(self._run_id, utc_now_iso(), status)
            logger.info("Security run #%d %s (%d findings)", self._run_id, status, len(self._findings))
            return self._run_id
        finally:
            self._prober = None
            self._db.close()

    def _scope_hosts(self) -> list[str]:
        return sorted({e.host for e in self._endpoints})

    def _persist_auth_metadata(self) -> None:
        with self._db.transaction():
            for name, prof in self._config.program.auth_profiles.items():
                self._store.record_auth_profile(name, prof.host, prof.header_name,
                                                prof.token_env, prof.cookie_env, prof.description)

    # -- active request plumbing -----------------------------------------------------

    def _auth_headers(self, host: str, context: str | None) -> dict[str, str]:
        if not context:
            return {}
        prof = self._config.program.auth_profiles.get(context)
        if prof is None:
            return {}
        # resolve_header refuses cross-host; this is the only place auth material is attached.
        return prof.resolve_header(host)

    def _make_fetcher(self, endpoint: EndpointInfo, context: str | None = None):
        async def fetcher(req: CheckRequest) -> FetchRecord:
            headers = dict(req.headers)
            if self._config.program.researcher_header:
                headers.setdefault(*self._config.program.researcher_header)
            headers.update(self._auth_headers(endpoint.host, context))
            try:
                result = await self._prober.fetch(req.url, max_bytes=256 * 1024, headers=headers or None)
            except Exception as exc:  # a check request must never crash the run
                return FetchRecord(None, {}, "", None, error=str(exc))
            return FetchRecord(
                status=result.status_code,
                headers=dict(result.headers),
                body_excerpt=excerpt(result.text(2048)),
                final_url=result.final_url,
                error=(result.error_type.value if result.error_type else None),
            )
        return fetcher

    # -- stage: security analysis ----------------------------------------------------

    async def _stage_security_analysis(self) -> None:
        for endpoint in self._endpoints:
            in_scope = self._config.scope.classify_host(endpoint.host).value == "in_scope"
            operation = "write" if endpoint.method.upper() in ("POST", "PUT", "PATCH", "DELETE") else "read"
            decision = self._policy.decide(endpoint, operation=operation, in_scope=in_scope)
            with self._db.transaction():
                self._store.record_check(self._run_id, "policy", endpoint.host, endpoint.path,
                                         decision.policy.value, decision.reason,
                                         executed=decision.may_active, now=utc_now_iso())

            # Capture one baseline (used as evidence for passive + active checks).
            stored_headers: dict[str, str] = {}
            stored_body = ""
            stored_status: int | None = None
            if decision.may_active and self._config.enable_active:
                baseline = await self._safe_baseline(endpoint)
                if baseline is not None:
                    stored_headers, stored_body, stored_status = baseline

            ctx = CheckContext(
                endpoint=endpoint, decision=decision, governor=self._governor,
                fetcher=self._make_fetcher(endpoint),
                stored_headers=stored_headers, stored_body_excerpt=stored_body, stored_status=stored_status,
                program_mode=self._config.program.global_mode,
            )
            for check in PASSIVE_CHECKS:
                if check.supports(endpoint):
                    self._collect(await self._safe_run(check, ctx))
            if self._config.enable_active:
                for check in ACTIVE_CHECKS:
                    if check.supports(endpoint):
                        self._collect(await self._safe_run(check, ctx))
            # REVIEW_REQUIRED endpoints: emit a manual-validation finding + package.
            if decision.policy is TestingPolicy.REVIEW_REQUIRED:
                self._emit_manual(endpoint)

        # Optional Nuclei pass (bounded, safe profiles) over in-scope hosts.
        await self._run_nuclei()

    async def _safe_baseline(self, endpoint: EndpointInfo):
        key = f"baseline {endpoint.identity or endpoint.url()}"
        try:
            lease = await self._governor.acquire(endpoint.host, key)
        except BudgetExceeded:
            return None
        async with lease:
            headers = {}
            if self._config.program.researcher_header:
                headers[self._config.program.researcher_header[0]] = self._config.program.researcher_header[1]
            try:
                result = await self._prober.fetch(endpoint.url(), max_bytes=256 * 1024)
            except Exception:
                return None
        if result.status_code is None:
            return None
        return dict(result.headers), excerpt(result.text(2048)), result.status_code

    async def _safe_run(self, check, ctx: CheckContext) -> list[Finding]:
        try:
            return await check.run(ctx)
        except Exception as exc:
            logger.debug("Check %s errored on %s: %s", getattr(check, "check_id", "?"), ctx.endpoint.path, exc)
            return []

    def _collect(self, findings: list[Finding]) -> None:
        self._findings.extend(findings)

    def _emit_manual(self, endpoint: EndpointInfo) -> None:
        interesting_params = [p for p in endpoint.param_names
                              if classify_parameter(p) is not ParamClass.GENERIC]
        finding = Finding(
            check_id="policy.manual_required", asset=endpoint.host, category="manual_review",
            title=f"Manual validation required: {endpoint.method} {endpoint.path}",
            confidence=0.5, severity_hint="info", endpoint=endpoint.path,
            parameter=interesting_params[0] if interesting_params else None,
            review_priority=40 + relevance_score(endpoint) // 3,
            validation_state=ValidationState.MANUAL_VALIDATION_REQUIRED, source="policy",
        )
        self._collect([finding])

    async def _run_nuclei(self) -> None:
        adapter = self._components.nuclei_adapter
        if adapter is None:
            return
        from .nuclei import parse_findings
        hosts = [f"https://{h}/" for h in self._scope_hosts()]
        try:
            lines = await asyncio.to_thread(adapter.run, hosts)
        except Exception as exc:
            logger.warning("Nuclei run failed: %s", exc)
            return
        self._collect(parse_findings(lines))

    # -- stage: validation (access-context differential, read-only) ------------------

    async def _stage_validation(self) -> None:
        contexts = self._config.auth_contexts
        if not contexts:
            return
        for endpoint in self._endpoints:
            if endpoint.method.upper() not in ("GET", "HEAD", "UNKNOWN"):
                continue   # state-changing authz validation is REVIEW_REQUIRED, handled elsewhere
            refs = object_reference_candidates(endpoint.host, endpoint.path, endpoint.param_names)
            if not refs:
                continue
            decision = self._policy.decide(endpoint, operation="read")
            if not decision.may_active:
                continue
            responses = {}
            for context in ("anonymous", *contexts):
                record = await self._context_fetch(endpoint, None if context == "anonymous" else context)
                if record is not None:
                    responses[context] = observe(context, record.status, record.body_excerpt)
            if len(responses) >= 2:
                self._collect(compare_contexts(endpoint.host, endpoint.path, responses))

    async def _context_fetch(self, endpoint: EndpointInfo, context: str | None):
        key = f"authz {context or 'anonymous'} {endpoint.identity or endpoint.url()}"
        try:
            lease = await self._governor.acquire(endpoint.host, key, check_budget=(f"authz:{endpoint.host}", 6))
        except BudgetExceeded:
            return None
        fetcher = self._make_fetcher(endpoint, context)
        async with lease:
            return await fetcher(CheckRequest("GET", endpoint.url(), note=f"authz diff: {context}"))

    # -- stage: correlation ----------------------------------------------------------

    async def _stage_correlation(self) -> None:
        deduped = deduplicate(self._findings)
        now = utc_now_iso()
        with self._db.transaction():
            for finding in deduped:
                fid = self._store.upsert_finding(finding, now)
                self._finding_ids[finding.dedup_key] = fid
                if finding.validation_state is ValidationState.MANUAL_VALIDATION_REQUIRED:
                    endpoint = self._endpoint_for(finding)
                    pkg = build_package(finding, endpoint,
                                        required_auth=self._config.auth_contexts[0] if self._config.auth_contexts else None)
                    self._store.add_manual_package(fid, finding.asset, finding.endpoint, pkg, now)
                self._build_graph(finding, fid, now)
        self._findings = deduped

    def _endpoint_for(self, finding: Finding) -> EndpointInfo | None:
        for e in self._endpoints:
            if e.host == finding.asset and e.path == finding.endpoint:
                return e
        return None

    def _build_graph(self, finding: Finding, fid: int, now: str) -> None:
        asset_node = self._store.node("asset", finding.asset, now=now)
        finding_node = self._store.node("finding", finding.dedup_key, label=finding.title, now=now)
        self._store.edge(finding_node, asset_node, "DISCOVERED_FROM")
        if finding.endpoint:
            ep_node = self._store.node("endpoint", f"{finding.asset}{finding.endpoint}", now=now)
            self._store.edge(ep_node, asset_node, "RUNS_ON")
            self._store.edge(finding_node, ep_node, "SUPPORTED_BY")
            if finding.parameter:
                p_node = self._store.node("parameter", finding.parameter, now=now)
                self._store.edge(ep_node, p_node, "USES_PARAMETER")

    # -- stage: AI -------------------------------------------------------------------

    async def _stage_ai(self) -> None:
        if not self._config.enable_ai:
            return
        provider = self._components.ai_provider or MockProvider()
        analyzer = AIAnalyzer(provider, self._config.ai, cache={})
        now = utc_now_iso()
        # Group findings by (asset, endpoint); analyze only high-priority items.
        for finding in sorted(self._findings, key=lambda f: f.review_priority, reverse=True):
            fp_cached = None
            bundle = EvidenceBundle(
                asset=finding.asset, endpoint=finding.endpoint,
                facts={
                    "category": finding.category, "title": finding.title,
                    "validation_state": finding.validation_state.value,
                    "evidence": [e.summary for e in finding.evidence][:6],
                    "parameter": finding.parameter,
                },
                untrusted_excerpts=[str(e.data.get("body", "")) for e in finding.evidence if e.data.get("body")][:3],
                review_priority=finding.review_priority,
            )
            fp = bundle.fingerprint()
            cached = self._store.ai_cached(fp)
            if cached is not None:
                continue
            result = analyzer.analyze(bundle, "Propose non-destructive manual security tests for this endpoint.")
            if result is None:
                continue
            with self._db.transaction():
                self._store.store_ai(fp, finding.asset, finding.endpoint, provider.name,
                                     result["hypotheses"], now)
