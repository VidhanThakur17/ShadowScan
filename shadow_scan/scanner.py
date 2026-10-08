"""Run orchestration: bounded probe producers feeding a single database writer.

    targets --> [semaphore-bounded probe tasks] --> asyncio.Queue --> [writer task] --> DB thread
                (share one ClientSession)          (bounded:          (batches by size     (one sqlite
                                                    backpressure)      or time)             connection)

* The semaphore bounds how many probes run at once. The bounded queue stops
  fast probes from piling up results in memory when the database falls behind.
* A single writer task owns all persistence. Every SQLite call runs in one
  dedicated worker thread, so the event loop never blocks on disk I/O and
  SQLite never sees concurrent writers.
* Change detection runs inside the same transaction that inserts the new
  observation. "Previous observation" is therefore always consistent with
  what has been committed.
"""

from __future__ import annotations

import asyncio
import functools
import logging
import time
from collections import Counter
from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor
from typing import Any, TypeVar

from .config import ScanConfig
from .database import Database
from .delta import compare_content, detect_changes, sort_changes
from .fingerprint import FingerprintEngine
from .http_probe import HttpProber
from .models import AssetHistory, Change, ErrorType, ProbeResult, RunStatus, RunSummary, Target
from .utils import CHANGE, ScopePolicy, utc_now_iso

logger = logging.getLogger(__name__)

T = TypeVar("T")

# Routine failures for large subdomain lists: logged at DEBUG to keep INFO output readable.
_QUIET_ERRORS = frozenset({ErrorType.DNS_FAILURE})


class Scanner:
    """Executes one monitoring run over a fixed list of targets."""

    def __init__(
        self,
        config: ScanConfig,
        targets: Sequence[Target],
        engine: FingerprintEngine | None = None,
        http_resolver=None,
    ) -> None:
        config.validate()
        self._config = config
        self._targets = list(targets)
        self._scope = ScopePolicy.from_targets(self._targets, config.allow_subdomain_redirects)
        self._engine = engine or FingerprintEngine.default(
            config.normalization_max_bytes, config.similarity_max_bytes, config.similarity_chunk_divisor
        )
        self._http_resolver = http_resolver
        self._db = Database(config.database_path)
        self._executor: ThreadPoolExecutor | None = None
        self._run_id: int | None = None

        # Mutated only on the event loop thread: no locking needed.
        self._completed = 0
        self._persisted = 0
        self._reachable = 0
        self._unreachable = 0
        self._incomplete = 0
        self._raw_only = 0
        self._error_counts: Counter[str] = Counter()
        self._changes: list[Change] = []

    # -- public ------------------------------------------------------------------------

    async def run(self) -> RunSummary:
        """Run the scan. Returns a summary even when interrupted or failed.

        Cancellation (Ctrl+C) is converted into an ``interrupted`` run. Any
        result that was already queued is still persisted first.
        """
        started_at = utc_now_iso()
        started = time.perf_counter()
        status = RunStatus.FAILED
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="shadowscan-db")
        try:
            await self._db_call(self._db.open)
            self._run_id = await self._db_call(self._db.start_run, started_at, len(self._targets))
            logger.info(
                "Starting HTTP monitoring run #%d: %s targets, concurrency=%d",
                self._run_id, f"{len(self._targets):,}", self._config.concurrency,
            )
            try:
                await self._execute()
                status = RunStatus.COMPLETED
            except asyncio.CancelledError:
                status = RunStatus.INTERRUPTED
                task = asyncio.current_task()
                if task is not None:
                    task.uncancel()
                logger.warning("Run interrupted; persisted %s completed results", f"{self._persisted:,}")
            except Exception:
                logger.exception("Run failed")
            finished_at = utc_now_iso()
            try:
                await self._db_call(
                    self._db.finish_run, self._run_id, finished_at, status,
                    self._persisted, self._reachable, self._unreachable, len(self._changes),
                    self._incomplete, sum(1 for c in self._changes if c.interesting), self._raw_only,
                )
            except Exception:
                logger.exception("Could not record run completion")
                status = RunStatus.FAILED
        except Exception as exc:
            # Opening the database or creating the run row failed (incl. an unsupported schema).
            logger.error("Could not initialize the database at %s: %s", self._config.database_path, exc)
            logger.debug("Database initialization traceback", exc_info=True)
            finished_at = utc_now_iso()
        finally:
            try:
                await self._db_call(self._db.close)
            finally:
                self._executor.shutdown(wait=True)

        summary = RunSummary(
            run_id=self._run_id,
            started_at=started_at,
            finished_at=finished_at,
            status=status,
            targets_total=len(self._targets),
            targets_processed=self._persisted,
            reachable=self._reachable,
            unreachable=self._unreachable,
            incomplete=self._incomplete,
            raw_only_changes=self._raw_only,
            duration_seconds=time.perf_counter() - started,
            changes=list(self._changes),
            error_counts=dict(self._error_counts),
        )
        self._log_summary(summary)
        return summary

    # -- orchestration -------------------------------------------------------------------

    async def _execute(self) -> None:
        results: asyncio.Queue[ProbeResult | None] = asyncio.Queue(maxsize=self._config.concurrency * 2)
        writer = asyncio.create_task(self._writer_loop(results), name="shadowscan-writer")
        try:
            async with HttpProber(self._config, self._scope, self._engine, resolver=self._http_resolver) as prober:
                producer = asyncio.create_task(self._produce(prober, results), name="shadowscan-producer")
                try:
                    done, _ = await asyncio.wait({producer, writer}, return_when=asyncio.FIRST_COMPLETED)
                    if writer in done:
                        # The writer only returns early if it crashed. Stop probing and surface its error.
                        producer.cancel()
                        await asyncio.gather(producer, return_exceptions=True)
                        writer.result()
                        raise RuntimeError("database writer stopped unexpectedly")
                    producer.result()
                finally:
                    # Probes must stop before the session closes. Otherwise in-flight
                    # requests would fail with "session closed" and be stored as bogus errors.
                    if not producer.done():
                        producer.cancel()
                    await asyncio.gather(producer, return_exceptions=True)
        finally:
            # Persist everything already queued, including on interruption.
            if not writer.done():
                await results.put(None)
                await writer

    async def _produce(self, prober: HttpProber, results: asyncio.Queue[ProbeResult | None]) -> None:
        semaphore = asyncio.Semaphore(self._config.concurrency)
        # Acquiring before create_task bounds the number of live tasks, not just
        # the number of active requests. Memory stays flat for very large inputs.
        async with asyncio.TaskGroup() as group:
            for target in self._targets:
                await semaphore.acquire()
                group.create_task(self._probe_one(prober, target, results, semaphore))

    async def _probe_one(
        self,
        prober: HttpProber,
        target: Target,
        results: asyncio.Queue[ProbeResult | None],
        semaphore: asyncio.Semaphore,
    ) -> None:
        try:
            try:
                result = await prober.probe(target)
            except Exception as exc:
                # prober.probe already classifies errors. This guard ensures a bug
                # affecting one target can never cancel the TaskGroup (and so the run).
                logger.error("Internal error probing %s: %s", target.key, exc)
                logger.debug("Traceback for %s", target.key, exc_info=True)
                result = ProbeResult(
                    target=target,
                    url=target.candidate_urls(False)[0],
                    checked_at=utc_now_iso(),
                    error_type=ErrorType.UNEXPECTED_ERROR,
                    error_message=f"{type(exc).__name__}: {exc}"[:500],
                )
            await results.put(result)
            self._log_result(result)
            self._completed += 1
            if self._completed % self._config.progress_interval == 0:
                logger.info("%s/%s processed", f"{self._completed:,}", f"{len(self._targets):,}")
        finally:
            semaphore.release()

    async def _writer_loop(self, results: asyncio.Queue[ProbeResult | None]) -> None:
        batch: list[ProbeResult] = []
        while True:
            # Block indefinitely while idle; once a batch is open, flush it after the interval.
            timeout = self._config.db_flush_interval if batch else None
            try:
                async with asyncio.timeout(timeout):
                    item = await results.get()
            except TimeoutError:
                batch = await self._flush(batch)
                continue
            if item is None:
                await self._flush(batch)
                return
            batch.append(item)
            if len(batch) >= self._config.db_batch_size:
                batch = await self._flush(batch)

    async def _flush(self, batch: list[ProbeResult]) -> list[ProbeResult]:
        """Commit one batch, then update counters and log changes. Returns an empty batch."""
        if not batch:
            return batch
        changes, raw_only = await self._db_call(self._persist_batch, batch)
        # Counters are updated only after the commit, so the summary matches the database.
        for result in batch:
            self._persisted += 1
            if result.http_reachable:
                self._reachable += 1
                if not result.observation_complete:
                    self._incomplete += 1
            else:
                self._unreachable += 1
            if result.error_type is not None:
                self._error_counts[result.error_type.value] += 1
        self._raw_only += raw_only
        threshold = self._config.console_priority_threshold
        for change in sort_changes(changes):
            # Live output stays readable: low-priority changes are only shown with --verbose.
            level = CHANGE if change.interesting or change.review_priority >= threshold else logging.DEBUG
            logger.log(level, "[%d] %s %s", change.review_priority, change.target, change.describe())
        self._changes.extend(changes)
        return []

    def _persist_batch(self, batch: list[ProbeResult]) -> tuple[list[Change], int]:
        """Runs in the DB thread: a single transaction for the whole batch.

        Per result: O(1) primary-key lookups for the previous and baseline
        observations, one bounded similarity comparison (only if the content
        changed), then inserts and an incremental update of the asset's history.
        """
        db = self._db
        cfg = self._config
        detected: list[Change] = []
        raw_only = 0
        with db.transaction():
            for result in batch:
                asset = db.upsert_asset(result.target, result.checked_at)
                previous = db.get_observation(asset.last_observation_id)
                if asset.last_complete_observation_id == asset.last_observation_id:
                    baseline = previous
                else:
                    baseline = db.get_observation(asset.last_complete_observation_id)
                comparison = compare_content(
                    result, baseline,
                    lambda: db.get_baseline_sketch(asset.id, baseline.id) if baseline else None,
                )
                history = AssetHistory(
                    observations=asset.history.observations + 1,
                    content_comparisons=asset.history.content_comparisons + int(comparison.comparable),
                    content_changes=asset.history.content_changes + int(comparison.content_changed),
                )
                changes = detect_changes(
                    result, previous, baseline, comparison, history,
                    trivial_threshold=cfg.similarity_trivial_threshold,
                    major_threshold=cfg.similarity_major_threshold,
                )
                observation_id = db.insert_observation(
                    asset.id, self._run_id, result,
                    comparison.similarity if comparison.comparable else None, comparison.baseline_id,
                )
                db.insert_fingerprints(observation_id, result.fingerprints)
                complete = result.observation_complete
                db.update_asset_after_observation(
                    asset.id, observation_id, complete, history,
                    result.checked_at if comparison.content_changed else None,
                )
                if complete:
                    # The new complete observation becomes the content baseline; keep its sketch (or none).
                    db.set_baseline_sketch(
                        asset.id, observation_id, result.similarity_sketch,
                        content_unchanged=comparison.comparable and not comparison.content_changed,
                    )
                for change in changes:
                    db.insert_change(
                        self._run_id, asset.id, observation_id,
                        previous.id if previous else None, change, result.checked_at,
                    )
                detected.extend(changes)
                raw_only += int(comparison.raw_only)
        return detected, raw_only

    async def _db_call(self, fn: Callable[..., T], *args: Any) -> T:
        assert self._executor is not None
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(self._executor, functools.partial(fn, *args))

    # -- logging -------------------------------------------------------------------------

    @staticmethod
    def _log_result(result: ProbeResult) -> None:
        key = result.target.key
        if result.error_type is None:
            logger.debug("%s %s %s (%.0f ms)", key, result.status_code, result.final_url, result.response_time_ms or 0)
        elif result.error_type in _QUIET_ERRORS:
            logger.debug("%s %s: %s", key, result.error_type.value, result.error_message)
        else:
            logger.warning("%s %s: %s", key, result.error_type.value, result.error_message)

    @staticmethod
    def _log_summary(summary: RunSummary) -> None:
        # The human-readable summary block is printed by the CLI; this is the log-file record.
        logger.info(
            "Run #%s %s in %.1fs: %s processed, %d changes (%d interesting)",
            summary.run_id, summary.status.value, summary.duration_seconds,
            f"{summary.targets_processed:,}", len(summary.changes),
            sum(1 for c in summary.changes if c.interesting),
        )
        if summary.error_counts:
            breakdown = ", ".join(f"{name}={count}" for name, count in sorted(summary.error_counts.items()))
            logger.info("Errors by type: %s", breakdown)
