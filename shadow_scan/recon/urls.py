"""URL normalization, de-duplication, parameter extraction and safety checks.

Normalization gives one canonical string per logical URL so the inventory does
not grow duplicates: lower-cased scheme/host, default ports dropped, fragments
removed, query parameters sorted by name, and empty/`/` paths unified.

:func:`is_dangerous_path` flags URLs whose *GET* might change state (logout,
delete, admin actions, …). The crawler never follows these, so a recon crawl
cannot mutate application state through a well-known action link.
"""

from __future__ import annotations

import posixpath
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .models import ParamLocation, Parameter

_DEFAULT_PORTS = {"http": "80", "https": "443"}

# Path segments / verbs that commonly trigger state changes on GET.
_DANGEROUS_SEGMENTS = frozenset({
    "logout", "signout", "sign-out", "log-out", "delete", "remove", "destroy",
    "drop", "reset", "revoke", "disable", "enable", "deactivate", "activate",
    "unsubscribe", "purge", "wipe", "shutdown", "restart", "reboot", "kill",
    "approve", "reject", "cancel", "confirm", "verify", "grant", "impersonate",
    "logoff", "terminate", "clear",
})
_DANGEROUS_RE = re.compile(
    r"(?:^|[/_-])(" + "|".join(sorted(_DANGEROUS_SEGMENTS)) + r")(?:$|[/_.-])",
    re.IGNORECASE,
)
_ACTION_PARAM_RE = re.compile(r"\b(action|do|op|cmd|command)=(delete|remove|logout|disable|reset|drop)\b", re.IGNORECASE)

# Parameter names that are review-worthy to surface (NOT a vulnerability claim).
INTERESTING_PARAMS = frozenset({
    "admin", "role", "debug", "redirect", "url", "callback", "file", "path",
    "template", "command", "cmd", "query", "token", "key", "secret", "user_id",
    "account_id", "next", "return", "returnurl", "dest", "destination", "continue",
    "id", "uid", "access", "auth", "api_key", "apikey", "password", "passwd",
})


def normalize_url(raw: str, base: str | None = None) -> str | None:
    """Return a canonical absolute URL string, or ``None`` if it is not http(s).

    When ``base`` is given, relative references are resolved against it.
    """
    raw = (raw or "").strip()
    if not raw:
        return None
    if base:
        raw = _urljoin(base, raw)
    try:
        parts = urlsplit(raw)
    except ValueError:
        return None
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        return None
    host = (parts.hostname or "").lower().rstrip(".")
    if not host:
        return None
    netloc = f"[{host}]" if ":" in host else host
    if parts.port is not None and _DEFAULT_PORTS.get(scheme) != str(parts.port):
        netloc = f"{netloc}:{parts.port}"
    path = _normalize_path(parts.path)
    query = urlencode(sorted(parse_qsl(parts.query, keep_blank_values=True)))
    return urlunsplit((scheme, netloc, path, query, ""))


def _urljoin(base: str, ref: str) -> str:
    from urllib.parse import urljoin
    return urljoin(base, ref)


def _normalize_path(path: str) -> str:
    if not path:
        return "/"
    # Collapse ./ and ../ safely without touching the host.
    normalized = posixpath.normpath(path)
    if normalized == ".":
        normalized = "/"
    if path.endswith("/") and not normalized.endswith("/") and normalized != "/":
        normalized += "/"
    if not normalized.startswith("/"):
        normalized = "/" + normalized
    return normalized


def url_host(url: str) -> str | None:
    try:
        host = urlsplit(url).hostname
    except ValueError:
        return None
    return host.lower().rstrip(".") if host else None


def url_path(url: str) -> str:
    try:
        return _normalize_path(urlsplit(url).path)
    except ValueError:
        return "/"


def query_param_names(url: str) -> tuple[str, ...]:
    try:
        pairs = parse_qsl(urlsplit(url).query, keep_blank_values=True)
    except ValueError:
        return ()
    seen: list[str] = []
    for name, _ in pairs:
        if name and name not in seen:
            seen.append(name)
    return tuple(seen)


def query_parameters(url: str, source: str = "url") -> list[Parameter]:
    return [
        Parameter(name=name, location=ParamLocation.QUERY, source=source, confidence=0.9)
        for name in query_param_names(url)
    ]


def is_dangerous_path(url: str) -> bool:
    """True when a GET to this URL might change state and must not be crawled."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return True
    if _DANGEROUS_RE.search(parts.path or ""):
        return True
    if _ACTION_PARAM_RE.search(parts.query or ""):
        return True
    return False


def looks_like_js(url: str) -> bool:
    path = url_path(url).lower()
    return path.endswith(".js") or path.endswith(".mjs") or ".js?" in url.lower()
