"""Endpoint and parameter normalization and identity.

An endpoint discovered from HTML, JS, a historical URL and an OpenAPI spec must
collapse to one identity, not four copies. Identity is
``(host, METHOD, normalized_path)`` where the path has volatile segments
replaced by typed placeholders (``/api/users/123`` -> ``/api/users/{id}``), so
per-object paths unify while genuinely different routes stay distinct.

Methods are never assumed: an endpoint seen only as a URL has method
``UNKNOWN``, not ``GET``.
"""

from __future__ import annotations

import re

from .models import Endpoint, MethodConfidence, Parameter, ParamLocation
from .urls import INTERESTING_PARAMS, url_host, url_path

_NUMERIC_RE = re.compile(r"^\d+$")
_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)
_HEX_RE = re.compile(r"^[0-9a-f]{12,}$", re.IGNORECASE)
_LONGHASH_RE = re.compile(r"^[A-Za-z0-9_\-]{20,}$")
_EXISTING_PLACEHOLDER_RE = re.compile(r"^[:{].+[}]?$")


def normalize_path(path: str) -> str:
    """Replace volatile path segments with ``{id}``/``{uuid}``/``{hash}`` placeholders."""
    path = url_path(path)
    segments = path.split("/")
    out: list[str] = []
    for seg in segments:
        if not seg:
            out.append(seg)
            continue
        if _EXISTING_PLACEHOLDER_RE.match(seg):
            out.append("{id}")
        elif _NUMERIC_RE.match(seg):
            out.append("{id}")
        elif _UUID_RE.match(seg):
            out.append("{uuid}")
        elif _HEX_RE.match(seg) or (_LONGHASH_RE.match(seg) and any(c.isdigit() for c in seg)):
            out.append("{hash}")
        else:
            out.append(seg)
    normalized = "/".join(out)
    return normalized or "/"


def endpoint_from_url(url: str, *, method: str | None = None, source: str = "url", confidence: float = 0.5) -> Endpoint | None:
    host = url_host(url)
    if not host:
        return None
    return make_endpoint(host, url_path(url), method=method, source=source, confidence=confidence)


def make_endpoint(
    host: str,
    path: str,
    *,
    method: str | None = None,
    source: str = "unknown",
    confidence: float = 0.5,
    param_names: tuple[str, ...] = (),
) -> Endpoint:
    if method:
        resolved, conf = method.upper(), MethodConfidence.KNOWN
    else:
        resolved, conf = "UNKNOWN", MethodConfidence.UNKNOWN
    return Endpoint(
        host=host.lower().rstrip("."),
        path=normalize_path(path),
        method=resolved,
        method_confidence=conf,
        param_names=param_names,
        source=source,
        confidence=confidence,
    )


def identity_string(endpoint: Endpoint) -> str:
    host, method, path = endpoint.identity
    return f"{method} {host}{path}"


def merge_endpoints(endpoints: list[Endpoint]) -> list[Endpoint]:
    """Collapse endpoints sharing an identity, unioning params/sources and keeping
    the strongest method confidence and highest per-endpoint confidence."""
    merged: dict[tuple[str, str, str], Endpoint] = {}
    order = {MethodConfidence.UNKNOWN: 0, MethodConfidence.INFERRED: 1, MethodConfidence.KNOWN: 2}
    for ep in endpoints:
        key = ep.identity
        existing = merged.get(key)
        if existing is None:
            merged[key] = ep
            continue
        params = tuple(dict.fromkeys((*existing.param_names, *ep.param_names)))
        sources = ",".join(dict.fromkeys((*existing.source.split(","), *ep.source.split(","))))
        best = ep if order[ep.method_confidence] > order[existing.method_confidence] else existing
        merged[key] = Endpoint(
            host=existing.host, path=existing.path, method=best.method,
            method_confidence=best.method_confidence, param_names=params,
            source=sources, confidence=max(existing.confidence, ep.confidence),
        )
    return list(merged.values())


def is_interesting_param(name: str) -> bool:
    return name.lower() in INTERESTING_PARAMS


def merge_parameters(params: list[Parameter]) -> list[Parameter]:
    """De-duplicate parameters by (name, location, endpoint), unioning sources."""
    merged: dict[tuple[str, str, str | None], Parameter] = {}
    for p in params:
        key = (p.name.lower(), p.location.value, p.endpoint_identity)
        existing = merged.get(key)
        if existing is None:
            merged[key] = p
        else:
            sources = ",".join(dict.fromkeys((*existing.source.split(","), *p.source.split(","))))
            merged[key] = Parameter(
                name=existing.name, location=existing.location,
                endpoint_identity=existing.endpoint_identity, source=sources,
                confidence=max(existing.confidence, p.confidence),
            )
    return list(merged.values())


def parameter(name: str, location: ParamLocation, *, endpoint: str | None = None,
              source: str = "unknown", confidence: float = 0.5) -> Parameter:
    return Parameter(name=name, location=location, endpoint_identity=endpoint,
                     source=source, confidence=confidence)
