"""Request budgets and per-host rate limiting for active security checks.

Security analysis has its own limits, separate from recon. The :class:`RequestGovernor`
enforces, in addition to concurrency:

* a global cap per run (``max_requests_per_run``),
* a per-endpoint cap (``max_requests_per_endpoint``),
* a per-host token-bucket rate limit (``requests_per_second_per_host``).

Every active request must be admitted by :meth:`acquire` first; a refused
request is simply not sent. This makes accidental request explosions impossible
even if an individual check mis-behaves.
"""

from __future__ import annotations

import asyncio
import time
from collections import defaultdict
from dataclasses import dataclass


class BudgetExceeded(Exception):
    """Raised (and caught by the runner) when a request is refused by the governor."""


@dataclass(slots=True)
class _Bucket:
    tokens: float
    updated: float


class RequestGovernor:
    def __init__(
        self,
        *,
        max_requests_per_run: int = 500,
        max_requests_per_endpoint: int = 5,
        requests_per_second_per_host: float = 2.0,
        active_concurrency: int = 4,
        clock=time.monotonic,
    ) -> None:
        self._max_run = max_requests_per_run
        self._max_endpoint = max_requests_per_endpoint
        self._rps = max(0.01, requests_per_second_per_host)
        self._semaphore = asyncio.Semaphore(max(1, active_concurrency))
        self._clock = clock
        self._run_count = 0
        self._endpoint_counts: dict[str, int] = defaultdict(int)
        self._host_counts: dict[str, int] = defaultdict(int)
        self._buckets: dict[str, _Bucket] = {}
        self._check_counts: dict[str, int] = defaultdict(int)

    @property
    def total_requests(self) -> int:
        return self._run_count

    def host_requests(self, host: str) -> int:
        return self._host_counts[host]

    def _admit(self, host: str, endpoint_key: str, check_budget: tuple[str, int] | None) -> None:
        if self._run_count >= self._max_run:
            raise BudgetExceeded(f"run budget of {self._max_run} requests exhausted")
        if self._endpoint_counts[endpoint_key] >= self._max_endpoint:
            raise BudgetExceeded(f"per-endpoint budget of {self._max_endpoint} exhausted for {endpoint_key}")
        if check_budget is not None:
            key, limit = check_budget
            if self._check_counts[key] >= limit:
                raise BudgetExceeded(f"check budget of {limit} exhausted for {key}")

    async def _rate_wait(self, host: str) -> None:
        now = self._clock()
        bucket = self._buckets.get(host)
        if bucket is None:
            self._buckets[host] = _Bucket(tokens=self._rps - 1, updated=now)
            return
        elapsed = now - bucket.updated
        bucket.tokens = min(self._rps, bucket.tokens + elapsed * self._rps)
        bucket.updated = now
        if bucket.tokens < 1:
            delay = (1 - bucket.tokens) / self._rps
            await asyncio.sleep(delay)
            bucket.tokens = 0
            bucket.updated = self._clock()
        else:
            bucket.tokens -= 1

    async def acquire(self, host: str, endpoint_key: str, check_budget: tuple[str, int] | None = None):
        """Admit one active request or raise :class:`BudgetExceeded`.

        Returns an async context manager that holds a concurrency slot and
        records the request against all counters once entered.
        """
        self._admit(host, endpoint_key, check_budget)
        return _Lease(self, host, endpoint_key, check_budget)

    def _record(self, host: str, endpoint_key: str, check_budget: tuple[str, int] | None) -> None:
        self._run_count += 1
        self._endpoint_counts[endpoint_key] += 1
        self._host_counts[host] += 1
        if check_budget is not None:
            self._check_counts[check_budget[0]] += 1


class _Lease:
    def __init__(self, gov: RequestGovernor, host: str, endpoint_key: str, check_budget):
        self._gov = gov
        self._host = host
        self._endpoint_key = endpoint_key
        self._check_budget = check_budget

    async def __aenter__(self):
        # Re-check under the concurrency slot (another coroutine may have spent budget).
        await self._gov._semaphore.acquire()
        try:
            self._gov._admit(self._host, self._endpoint_key, self._check_budget)
        except BudgetExceeded:
            self._gov._semaphore.release()
            raise
        await self._gov._rate_wait(self._host)
        self._gov._record(self._host, self._endpoint_key, self._check_budget)
        return self

    async def __aexit__(self, *exc):
        self._gov._semaphore.release()
        return False
