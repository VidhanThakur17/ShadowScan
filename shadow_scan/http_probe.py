"""Asynchronous, scope-aware, size-bounded HTTP probing."""

from __future__ import annotations

import asyncio
import errno
import logging
import socket
import ssl
import time
from dataclasses import dataclass, field
from types import TracebackType
from typing import Self

import aiohttp
from yarl import URL

from .config import ScanConfig
from .fingerprint import FingerprintEngine, NormalizedContentFingerprinter, RawSha256Fingerprinter, ResponseInfo, extract_title
from .models import ErrorType, ProbeResult, Target
from .utils import ScopePolicy, utc_now_iso

logger = logging.getLogger(__name__)

REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})

# HTTPS failures that suggest "no HTTPS service here" rather than "host is
# gone". Only these trigger the HTTP fallback for scheme-less targets. A DNS
# failure would fail identically over HTTP, and a read timeout means the
# service exists, so neither one triggers a fallback.
FALLBACK_ERRORS = frozenset({
    ErrorType.CONNECTION_REFUSED,
    ErrorType.CONNECTION_TIMEOUT,
    ErrorType.CONNECTION_ERROR,
    ErrorType.TLS_ERROR,
})

_READ_CHUNK_SIZE = 64 * 1024
_MAX_ERROR_MESSAGE = 500
# ECONNREFUSED plus the Windows codes WSAECONNREFUSED / ERROR_CONNECTION_REFUSED.
_REFUSED_CODES = frozenset({errno.ECONNREFUSED, 10061, 1225})


def _short_message(exc: BaseException) -> str:
    text = " ".join(str(exc).split()) or "no details"
    message = f"{type(exc).__name__}: {text}"
    return message if len(message) <= _MAX_ERROR_MESSAGE else message[: _MAX_ERROR_MESSAGE - 3] + "..."


def _classify_os_error(err: BaseException | None) -> ErrorType:
    if isinstance(err, socket.gaierror):
        return ErrorType.DNS_FAILURE
    if isinstance(err, ConnectionRefusedError) or (
        isinstance(err, OSError)
        and (err.errno in _REFUSED_CODES or getattr(err, "winerror", None) in _REFUSED_CODES)
    ):
        return ErrorType.CONNECTION_REFUSED
    if isinstance(err, TimeoutError):
        return ErrorType.CONNECTION_TIMEOUT
    if isinstance(err, ssl.SSLError):
        return ErrorType.TLS_ERROR
    return ErrorType.CONNECTION_ERROR


def classify_exception(exc: BaseException) -> tuple[ErrorType, str]:
    """Map an exception raised while probing to an :class:`ErrorType`.

    Order matters because the aiohttp hierarchy overlaps. For example,
    ``ClientSSLError`` is a ``ClientConnectorError``, ``ConnectionTimeoutError``
    is a ``ServerTimeoutError``, and ``TimeoutError`` is an ``OSError``.
    """
    message = _short_message(exc)
    if isinstance(exc, (aiohttp.ClientConnectorCertificateError, aiohttp.ClientSSLError, ssl.SSLError)):
        return ErrorType.TLS_ERROR, message
    if isinstance(exc, aiohttp.ConnectionTimeoutError):
        return ErrorType.CONNECTION_TIMEOUT, message
    if isinstance(exc, aiohttp.ClientConnectorDNSError):
        return ErrorType.DNS_FAILURE, message
    if isinstance(exc, aiohttp.ClientConnectorError):
        return _classify_os_error(exc.os_error), message
    if isinstance(exc, (aiohttp.InvalidURL, ValueError)):
        return ErrorType.INVALID_URL, message
    if isinstance(exc, (aiohttp.ServerTimeoutError, TimeoutError)):
        return ErrorType.READ_TIMEOUT, message
    if isinstance(exc, aiohttp.ClientError):
        return ErrorType.CLIENT_ERROR, message
    if isinstance(exc, OSError):
        return _classify_os_error(exc), message
    return ErrorType.UNEXPECTED_ERROR, message


def _parse_int(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        parsed = int(value.strip())
    except ValueError:
        return None
    return parsed if parsed >= 0 else None


@dataclass(slots=True)
class FetchResult:
    """A bounded single-GET fetch for recon (crawler/JS/favicon/spec analysis)."""

    url: str
    status_code: int | None = None
    final_url: str | None = None
    content_type: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    set_cookie: str | None = None
    redirect_location: str | None = None
    body: bytes = b""
    truncated: bool = False
    error_type: ErrorType | None = None
    error_message: str | None = None

    @property
    def ok(self) -> bool:
        return self.status_code is not None and self.error_type is None

    def text(self, max_chars: int | None = None) -> str:
        charset = None
        if self.content_type and "charset=" in self.content_type.lower():
            charset = self.content_type.lower().split("charset=", 1)[1].split(";")[0].strip()
        try:
            decoded = self.body.decode(charset or "utf-8", errors="replace")
        except LookupError:
            decoded = self.body.decode("utf-8", errors="replace")
        return decoded[:max_chars] if max_chars else decoded


class HttpProber:
    """Probes targets using a single shared, connection-pooled ``ClientSession``.

    Use as an async context manager; the session is closed on exit.
    """

    def __init__(
        self,
        config: ScanConfig,
        scope: ScopePolicy,
        engine: FingerprintEngine | None = None,
        resolver: "aiohttp.abc.AbstractResolver | None" = None,
    ) -> None:
        self._config = config
        self._scope = scope
        self._engine = engine or FingerprintEngine.default(
            config.normalization_max_bytes, config.similarity_max_bytes, config.similarity_chunk_divisor
        )
        # Optional custom DNS resolver (e.g. offline tests mapping hosts to a local server).
        self._resolver = resolver
        self._session: aiohttp.ClientSession | None = None

    async def __aenter__(self) -> Self:
        cfg = self._config
        connector_kwargs = {"limit": cfg.concurrency, "ttl_dns_cache": 300, "ssl": cfg.verify_tls}
        if self._resolver is not None:
            connector_kwargs["resolver"] = self._resolver
        connector = aiohttp.TCPConnector(**connector_kwargs)
        timeout = aiohttp.ClientTimeout(
            total=cfg.total_timeout,         # hard ceiling per request; defeats slow-drip servers
            connect=cfg.request_timeout,     # pool acquire + DNS + TCP + TLS
            sock_read=cfg.request_timeout,
        )
        headers = {
            "User-Agent": cfg.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            **dict(cfg.extra_headers),
        }
        self._session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers=headers,
            # The session itself never stores cookies. Each probe keeps its own
            # ephemeral jar (see _probe_url), so cookies never cross targets or runs.
            cookie_jar=aiohttp.DummyCookieJar(),
            raise_for_status=False,
            max_line_size=16384,
            max_field_size=16384,
        )
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        if self._session is not None:
            await self._session.close()
            self._session = None

    async def fetch(self, url: str, *, max_bytes: int | None = None) -> FetchResult:
        """Fetch one in-scope URL's bounded body for recon analysis.

        Reuses the shared pooled session, timeouts, size cap and per-request
        ephemeral cookie jar, so recon crawling/JS/favicon fetching does not
        become a second HTTP system. Redirects are NOT followed here: the
        caller (crawler) decides, so every hop stays scope-checked. Never
        raises except ``CancelledError``.
        """
        assert self._session is not None, "HttpProber must be used as an async context manager"
        limit = max_bytes if max_bytes is not None else self._config.max_response_bytes
        result = FetchResult(url=url)
        try:
            # The session's DummyCookieJar keeps this stateless; no cookies persist across fetches.
            async with self._session.get(url, allow_redirects=False) as response:
                result.status_code = response.status
                result.final_url = str(response.url)
                result.content_type = response.headers.get("Content-Type")
                result.headers = {k: v for k, v in response.headers.items()}
                if response.headers.get("Set-Cookie"):
                    result.set_cookie = response.headers.get("Set-Cookie")
                if response.status in REDIRECT_STATUSES:
                    result.redirect_location = response.headers.get("Location")
                body = bytearray()
                async for chunk in response.content.iter_chunked(_READ_CHUNK_SIZE):
                    remaining = limit - len(body)
                    if len(chunk) > remaining:
                        body += chunk[:remaining]
                        result.truncated = True
                        response.close()
                        break
                    body += chunk
                result.body = bytes(body)
        except Exception as exc:  # CancelledError is BaseException and propagates
            result.error_type, result.error_message = classify_exception(exc)
            if result.error_type is ErrorType.UNEXPECTED_ERROR:
                logger.debug("Unexpected error fetching %s", url, exc_info=True)
        return result

    async def probe(self, target: Target) -> ProbeResult:
        """Probe one target. Never raises except for ``CancelledError``."""
        urls = target.candidate_urls(self._config.http_fallback)
        result = await self._probe_url(target, urls[0])
        if len(urls) > 1 and not result.reachable and result.error_type in FALLBACK_ERRORS:
            logger.debug("%s HTTPS unavailable (%s), trying HTTP", target.key, result.error_type)
            fallback = await self._probe_url(target, urls[1])
            if fallback.reachable:
                fallback.fallback_used = True
                return fallback
            result.error_message = (
                f"{result.error_message} | HTTP fallback failed: {fallback.error_type}: {fallback.error_message}"
            )
        return result

    async def _probe_url(self, target: Target, url: str) -> ProbeResult:
        """Request ``url`` and follow in-scope redirects manually.

        Redirects are handled here and not by aiohttp. That way every hop is
        checked against the scope policy *before* it is requested, and loops and
        limits are reported as distinct error types.

        Cookies: a fresh in-memory jar lives only for this one redirect chain.
        It lets "set cookie, redirect to self" flows complete instead of
        looking like loops. The jar is never shared with another target, the
        HTTPS/HTTP fallback attempt, or a later run, and its cookies are only
        ever sent to in-scope URLs, because only in-scope URLs are requested.
        """
        assert self._session is not None, "HttpProber must be used as an async context manager"
        result = ProbeResult(target=target, url=url, checked_at=utc_now_iso())
        started = time.perf_counter()
        # unsafe=True only means "accept cookies set by IP-address hosts"; the jar is per-probe.
        jar = aiohttp.CookieJar(unsafe=True)
        current = url
        visited: set[tuple[str, str]] = set()
        try:
            while True:
                cookie_header = self._cookie_header(jar, current)
                visited.add((current, cookie_header))
                headers = {"Cookie": cookie_header} if cookie_header else None
                async with self._session.get(current, allow_redirects=False, headers=headers) as response:
                    self._record_response(result, response)
                    jar.update_cookies(response.cookies, response.url)
                    next_url = self._next_hop(response, result, visited, jar)
                    if next_url is None:
                        await self._consume_body(response, result)
                        break
                # Exiting the context released the redirect response before the next hop.
                result.redirect_count += 1
                current = next_url
        except Exception as exc:  # CancelledError is a BaseException and deliberately propagates
            result.error_type, result.error_message = classify_exception(exc)
            if result.error_type is ErrorType.UNEXPECTED_ERROR:
                logger.debug("Unexpected error probing %s", current, exc_info=True)
        result.response_time_ms = round((time.perf_counter() - started) * 1000, 2)
        return result

    @staticmethod
    def _cookie_header(jar: aiohttp.CookieJar, url: str) -> str:
        cookies = jar.filter_cookies(URL(url))
        return "; ".join(f"{morsel.key}={morsel.coded_value}" for morsel in cookies.values())

    @staticmethod
    def _record_response(result: ProbeResult, response: aiohttp.ClientResponse) -> None:
        headers = response.headers
        result.final_url = str(response.url)
        result.scheme = response.url.scheme
        result.hostname = response.url.host
        result.status_code = response.status
        result.content_type = headers.get("Content-Type")
        result.content_length_header = _parse_int(headers.get("Content-Length"))
        result.server_header = headers.get("Server")

    def _next_hop(
        self,
        response: aiohttp.ClientResponse,
        result: ProbeResult,
        visited: set[tuple[str, str]],
        jar: aiohttp.CookieJar,
    ) -> str | None:
        """Return the URL to follow next, or ``None`` if this response is terminal.

        Records ``redirect_location`` and loop/limit errors on ``result``.
        """
        if response.status not in REDIRECT_STATUSES:
            return None
        raw_location = response.headers.get("Location")
        if not raw_location:
            return None
        destination = response.url.join(URL(raw_location.strip())).with_fragment(None)
        location = str(destination)
        result.redirect_location = location

        if destination.scheme not in ("http", "https") or not self._scope.allows(destination.host):
            # Out of scope: record where it points, but never request it.
            logger.debug("%s redirect to out-of-scope %s not followed", result.target.key, location)
            return None
        # A revisit counts as a loop only if the cookie state is also unchanged.
        # A redirect to self that just set a cookie is legitimate.
        if (location, self._cookie_header(jar, location)) in visited:
            result.error_type = ErrorType.REDIRECT_LOOP
            result.error_message = f"redirect loop at {location}"
            return None
        if result.redirect_count >= self._config.max_redirects:
            result.error_type = ErrorType.REDIRECT_LIMIT_EXCEEDED
            result.error_message = f"more than {self._config.max_redirects} redirects (next: {location})"
            return None
        return location

    async def _consume_body(self, response: aiohttp.ClientResponse, result: ProbeResult) -> None:
        """Stream at most ``max_response_bytes`` into the fingerprinters.

        Only the first ``title_scan_bytes`` are kept, for title extraction, so
        memory per in-flight probe stays small no matter how large the body is.
        """
        limit = self._config.max_response_bytes
        head_limit = self._config.title_scan_bytes
        session = self._engine.new_session(
            ResponseInfo(
                url=result.final_url,
                status=result.status_code,
                content_type=result.content_type,
                headers=response.headers,
            )
        )
        head = bytearray()
        total = 0
        truncated = False

        async for chunk in response.content.iter_chunked(_READ_CHUNK_SIZE):
            remaining = limit - total
            if len(chunk) > remaining:
                chunk = chunk[:remaining]
                truncated = True
            if chunk:
                total += len(chunk)
                session.update(chunk)
                if len(head) < head_limit:
                    head += chunk[: head_limit - len(head)]
            if truncated:
                break

        if truncated:
            # Drop the connection rather than draining an arbitrarily large remainder.
            response.close()
            if result.error_type is None:
                result.error_type = ErrorType.RESPONSE_TOO_LARGE
                result.error_message = f"body exceeded {limit} bytes; hashed the first {limit} bytes only"

        result.downloaded_bytes = total
        result.body_truncated = truncated
        if total > self._config.cpu_offload_bytes:
            # Normalizing and sketching a large text body is CPU work: keep it off the event loop.
            fingerprints = await asyncio.to_thread(session.finalize, truncated)
        else:
            fingerprints = session.finalize(truncated)
        result.fingerprints = fingerprints.values
        result.similarity_sketch = fingerprints.similarity_sketch
        result.body_sha256 = fingerprints.values.get(RawSha256Fingerprinter.name)
        result.normalized_sha256 = fingerprints.values.get(NormalizedContentFingerprinter.name)
        result.title = extract_title(bytes(head), result.content_type, response.charset)
