"""Centralized retry classification and bounded backoff.

Not every error deserves a retry. Errors are classified; retryable ones use
bounded exponential backoff with jitter. Policy denials are NEVER retried
automatically. There are no infinite loops: attempts are hard-capped.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from enum import StrEnum


class RetryClass(StrEnum):
    RETRYABLE = "retryable"
    NOT_RETRYABLE = "not_retryable"
    STORE_FOR_REVIEW = "store_for_review"   # e.g. parser failures: keep, don't loop
    NEVER = "never"                         # policy denial: never auto-retry


# error-type (as used across ShadowScan) -> classification
_CLASSIFICATION: dict[str, RetryClass] = {
    "connection_timeout": RetryClass.RETRYABLE,
    "read_timeout": RetryClass.RETRYABLE,
    "timeout": RetryClass.RETRYABLE,
    "connection_error": RetryClass.RETRYABLE,
    "connection_refused": RetryClass.NOT_RETRYABLE,
    "servfail": RetryClass.RETRYABLE,
    "dns_temporary": RetryClass.RETRYABLE,
    "dns_failure": RetryClass.NOT_RETRYABLE,
    "nxdomain": RetryClass.NOT_RETRYABLE,
    "tls_error": RetryClass.NOT_RETRYABLE,
    "invalid_url": RetryClass.NOT_RETRYABLE,
    "http_403": RetryClass.NOT_RETRYABLE,
    "http_401": RetryClass.NOT_RETRYABLE,
    "parser_failure": RetryClass.STORE_FOR_REVIEW,
    "ai_temporary": RetryClass.RETRYABLE,
    "ai_rate_limit": RetryClass.RETRYABLE,
    "policy_denied": RetryClass.NEVER,
}


def classify(error_type: str | None) -> RetryClass:
    if not error_type:
        return RetryClass.NOT_RETRYABLE
    return _CLASSIFICATION.get(error_type.lower(), RetryClass.NOT_RETRYABLE)


def should_retry(error_type: str | None, attempt: int, max_attempts: int = 3) -> bool:
    return attempt < max_attempts and classify(error_type) is RetryClass.RETRYABLE


@dataclass(frozen=True, slots=True)
class Backoff:
    base: float = 0.5
    factor: float = 2.0
    max_delay: float = 30.0
    jitter: float = 0.25

    def delay(self, attempt: int, *, rng: random.Random | None = None) -> float:
        """Delay before ``attempt`` (1-based). Bounded; jitter avoids thundering herd."""
        rng = rng or random
        raw = min(self.max_delay, self.base * (self.factor ** max(0, attempt - 1)))
        return max(0.0, raw + rng.uniform(-self.jitter * raw, self.jitter * raw))
