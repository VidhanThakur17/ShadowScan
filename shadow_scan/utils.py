"""Target loading/normalization, redirect scope policy, time and logging helpers."""

from __future__ import annotations

import ipaddress
import logging
import re
import sys
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

from .models import Target

logger = logging.getLogger(__name__)

# Custom level between INFO (20) and WARNING (30) so deltas stand out in the log.
CHANGE = 25
logging.addLevelName(CHANGE, "CHANGE")

_ALLOWED_SCHEMES = frozenset({"http", "https"})
_DEFAULT_PORTS = {"http": 80, "https": 443}
# Underscores are technically invalid in hostnames but common in real DNS records.
_LABEL_RE = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$")


class InvalidTargetError(ValueError):
    """Raised when an input line cannot be turned into a safe target."""


def utc_now_iso() -> str:
    """Current UTC time as an ISO-8601 string with millisecond precision."""
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _normalize_hostname(raw_host: str) -> str:
    host = raw_host.strip().lower().rstrip(".")
    if not host:
        raise InvalidTargetError("missing hostname")
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    if not host.isascii():
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise InvalidTargetError(f"invalid internationalized hostname: {exc}") from None
    if len(host) > 253 or not all(_LABEL_RE.match(label) for label in host.split(".")):
        raise InvalidTargetError(f"invalid hostname {host!r}")
    return host


def normalize_target(raw: str) -> Target:
    """Turn one input line into a canonical :class:`Target`.

    * the asset key is ``host[:port][/path]`` without a scheme (host-based identity);
    * explicit ``http://`` / ``https://`` schemes are preserved as intent (``Target.scheme``);
    * hostnames are lower-cased, IDNA-encoded and stripped of a trailing dot;
    * default ports, a bare ``/`` path and URL fragments are dropped;
    * credentials in the URL and wildcard hosts are rejected.
    """
    text = raw.strip()
    if not text:
        raise InvalidTargetError("empty target")

    scheme: str | None = None
    if "://" in text:
        scheme = text.split("://", 1)[0].lower()
        if scheme not in _ALLOWED_SCHEMES:
            raise InvalidTargetError(f"unsupported scheme {scheme!r}")
        parts = urlsplit(text)
    else:
        parts = urlsplit(f"//{text}")

    if parts.username is not None or parts.password is not None:
        raise InvalidTargetError("credentials in target URLs are not allowed")
    if parts.hostname is None:
        raise InvalidTargetError("missing hostname")
    if "*" in parts.hostname:
        raise InvalidTargetError("wildcard hosts cannot be probed directly")

    hostname = _normalize_hostname(parts.hostname)
    try:
        port = parts.port
    except ValueError:
        raise InvalidTargetError("invalid port") from None
    if port == 0:
        raise InvalidTargetError("invalid port")
    if port is not None and scheme is not None and _DEFAULT_PORTS[scheme] == port:
        port = None

    path = parts.path if parts.path not in ("", "/") else ""
    if parts.query:
        path = f"{path or '/'}?{parts.query}"

    target = Target(key="", hostname=hostname, port=port, path=path, scheme=scheme)
    return Target(key=f"{target.netloc}{path}", hostname=hostname, port=port, path=path, scheme=scheme, original=text)


@dataclass(slots=True)
class LoadStats:
    lines: int = 0
    skipped_blank: int = 0
    invalid: int = 0
    duplicates: int = 0
    unique: int = 0


def parse_targets(lines: Iterable[str]) -> tuple[list[Target], LoadStats]:
    """Normalize and de-duplicate targets, preserving first-seen input order.

    Blank lines and ``#`` comment lines are ignored; invalid lines are logged
    and skipped so one bad entry never aborts loading.

    Lines that map to the same asset are merged. An explicit scheme wins over
    "auto", so ``example.com`` plus ``https://example.com`` is probed as
    HTTPS-only and never silently downgraded. Two different explicit schemes
    for one asset keep the first and log a warning.
    """
    stats = LoadStats()
    index: dict[str, int] = {}
    targets: list[Target] = []
    for lineno, line in enumerate(lines, start=1):
        stats.lines += 1
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            stats.skipped_blank += 1
            continue
        try:
            target = normalize_target(stripped)
        except InvalidTargetError as exc:
            stats.invalid += 1
            logger.warning("Skipping invalid target on line %d (%r): %s", lineno, stripped[:200], exc)
            continue
        position = index.get(target.key)
        if position is not None:
            stats.duplicates += 1
            existing = targets[position]
            if existing.scheme is None and target.scheme is not None:
                targets[position] = target
            elif existing.scheme and target.scheme and existing.scheme != target.scheme:
                logger.warning(
                    "Line %d (%r) conflicts with %r for the same asset; keeping %s",
                    lineno, stripped[:200], existing.original, existing.scheme,
                )
            continue
        index[target.key] = len(targets)
        targets.append(target)
    stats.unique = len(targets)
    return targets, stats


def load_targets(path: Path) -> tuple[list[Target], LoadStats]:
    """Read and parse a targets file (UTF-8, BOM tolerated)."""
    with path.open("r", encoding="utf-8-sig", errors="replace") as handle:
        return parse_targets(handle)


class ScopePolicy:
    """Decides whether a redirect destination may be requested.

    Scope is the set of hostnames supplied in the input. Redirects to any other
    host are recorded but never followed. With ``allow_subdomains`` a host is
    also in scope when it is a subdomain of a supplied hostname.
    """

    def __init__(self, hostnames: Iterable[str], allow_subdomains: bool = False) -> None:
        self._hosts = frozenset(h.lower().rstrip(".") for h in hostnames)
        self._allow_subdomains = allow_subdomains

    @classmethod
    def from_targets(cls, targets: Iterable[Target], allow_subdomains: bool = False) -> ScopePolicy:
        return cls((t.hostname for t in targets), allow_subdomains)

    def allows(self, hostname: str | None) -> bool:
        if not hostname:
            return False
        host = hostname.lower().rstrip(".")
        if host in self._hosts:
            return True
        if not self._allow_subdomains:
            return False
        labels = host.split(".")
        # Check every proper parent suffix: a.b.example.com -> b.example.com, example.com, com
        return any(".".join(labels[i:]) in self._hosts for i in range(1, len(labels)))


def configure_logging(verbose: bool = False) -> None:
    """Concise single-line logging; tracebacks only appear at DEBUG level."""
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S"))
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(logging.DEBUG if verbose else logging.INFO)
    # Third-party internals are only interesting when debugging.
    for noisy in ("aiohttp", "asyncio"):
        logging.getLogger(noisy).setLevel(logging.DEBUG if verbose else logging.WARNING)
