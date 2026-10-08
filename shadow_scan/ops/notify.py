"""Notification engine: structured events, filtering, dedup and safety.

Providers (console/file/webhook) are abstracted and never hard-depend on
third-party SDKs. Events are filtered per program (min priority + categories),
deduplicated across runs via the ops ledger, and **redacted** before delivery —
no auth headers, no secrets, only what identifies the issue. Webhook delivery
uses the stdlib and degrades gracefully if offline.
"""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol

from ..secanalysis.findings import redact

logger = logging.getLogger(__name__)


class EventType(StrEnum):
    NEW_HIGH_PRIORITY_REVIEW_ITEM = "new_high_priority_review_item"
    NEW_VALIDATED_FINDING = "new_validated_finding"
    NEW_HOST = "new_host"
    NEW_JS_ENDPOINT = "new_js_endpoint"
    HOST_BECAME_LIVE = "host_became_live"
    AUTHORIZATION_REVIEW_REQUIRED = "authorization_review_required"
    TAKEOVER_CANDIDATE = "takeover_candidate"
    FINDING_REGRESSED = "finding_regressed"
    RUN_FAILED = "run_failed"
    RUN_COMPLETED = "run_completed"


# Low-value events notified only in a run summary, never immediately, by default.
_SUMMARY_ONLY = {EventType.NEW_HOST, EventType.NEW_JS_ENDPOINT}


@dataclass(frozen=True, slots=True)
class Event:
    event_type: EventType
    program: str
    title: str
    priority: int = 0
    category: str | None = None
    dedup_key: str = ""
    asset: str | None = None
    detail: dict[str, Any] = field(default_factory=dict)

    def safe_payload(self) -> dict[str, Any]:
        """Redacted, minimal payload safe for external delivery."""
        return {
            "event": self.event_type.value,
            "program": self.program,
            "title": redact(self.title),
            "priority": self.priority,
            "category": self.category,
            "asset": self.asset,
            # Only scalar, redacted detail values; never raw bodies/headers/secrets.
            "detail": {k: (redact(v) if isinstance(v, str) else v)
                       for k, v in self.detail.items() if isinstance(v, (str, int, float, bool))},
        }


class NotificationProvider(Protocol):
    name: str

    def send(self, event: Event) -> bool: ...


class ConsoleProvider:
    name = "console"

    def __init__(self, sink=None) -> None:
        self._sink = sink or (lambda line: print(line, flush=True))

    def send(self, event: Event) -> bool:
        p = event.safe_payload()
        self._sink(f"[notify {p['priority']:>3}] {p['event']}: {p['title']} ({p['asset'] or event.program})")
        return True


class FileProvider:
    name = "file"

    def __init__(self, path: Path | str) -> None:
        self._path = Path(path)

    def send(self, event: Event) -> bool:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with self._path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(event.safe_payload(), ensure_ascii=False) + "\n")
            return True
        except OSError as exc:
            logger.warning("File notification failed: %s", exc)
            return False


class WebhookProvider:
    name = "webhook"

    def __init__(self, url: str, *, timeout: float = 5.0, opener=None) -> None:
        self._url = url
        self._timeout = timeout
        self._opener = opener   # injectable for tests; must accept (request, timeout)

    def send(self, event: Event) -> bool:
        data = json.dumps(event.safe_payload(), ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(self._url, data=data, headers={"Content-Type": "application/json"})
        try:
            if self._opener is not None:
                self._opener(req, self._timeout)
            else:  # pragma: no cover - real network path, not exercised offline
                urllib.request.urlopen(req, timeout=self._timeout).close()
            return True
        except (urllib.error.URLError, OSError, Exception) as exc:
            logger.warning("Webhook notification failed: %s", exc)
            return False


@dataclass(slots=True)
class NotificationConfig:
    min_priority: int = 80
    categories: tuple[str, ...] = ()
    immediate: bool = True       # False => collect for the run summary only


class Notifier:
    """Filters, deduplicates and dispatches events to providers."""

    def __init__(self, providers: list[NotificationProvider], config: NotificationConfig,
                 store, program: str) -> None:
        self._providers = providers
        self._config = config
        self._store = store        # OpsStore (for dedup ledger); may be None in tests
        self._program = program
        self.suppressed = 0
        self.sent = 0
        self.deferred: list[Event] = []

    def _passes_filter(self, event: Event) -> bool:
        if event.event_type in (EventType.RUN_FAILED, EventType.RUN_COMPLETED):
            return True
        if event.priority < self._config.min_priority:
            return False
        if self._config.categories and event.category and event.category not in self._config.categories:
            return False
        return True

    def emit(self, event: Event, now: str) -> bool:
        """Deliver an event if it passes filters and is not a duplicate. Returns delivered?"""
        if not self._passes_filter(event):
            self.suppressed += 1
            return False
        if event.event_type in _SUMMARY_ONLY and self._config.immediate:
            # Low-value: hold for the summary rather than an immediate ping.
            self.deferred.append(event)
            return False
        dedup = event.dedup_key or f"{event.event_type.value}:{event.asset or event.title}"
        if self._store is not None:
            fresh = self._store.record_notification(self._program, event.event_type.value, dedup, event.priority, now)
            if not fresh:
                self.suppressed += 1
                return False
        delivered = False
        for provider in self._providers:
            try:
                delivered = provider.send(event) or delivered
            except Exception as exc:  # a provider must never crash the run
                logger.warning("Notification provider %s failed: %s", getattr(provider, "name", "?"), exc)
        if delivered:
            self.sent += 1
        return delivered


def build_providers(names: tuple[str, ...], *, file_path: Path | None = None,
                    webhook_url: str | None = None, console_sink=None,
                    webhook_opener=None) -> list[NotificationProvider]:
    providers: list[NotificationProvider] = []
    for name in names:
        if name == "console":
            providers.append(ConsoleProvider(console_sink))
        elif name == "file" and file_path is not None:
            providers.append(FileProvider(file_path))
        elif name == "webhook" and webhook_url:
            providers.append(WebhookProvider(webhook_url, opener=webhook_opener))
    return providers
