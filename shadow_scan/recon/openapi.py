"""OpenAPI / Swagger parsing and GraphQL candidate recognition.

Parsing is bounded and passive: a document that is already available (linked,
or at a conventional path) is parsed when it is valid JSON. No wordlist brute
force and no GraphQL introspection happen here — introspection is explicitly
out of scope for this milestone. GraphQL support is limited to recognizing
*candidate* endpoints from clues.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from .endpoints import make_endpoint
from .models import Endpoint, Parameter, ParamLocation

_HTTP_METHODS = frozenset({"get", "post", "put", "patch", "delete", "head", "options", "trace"})
_PARAM_LOCATIONS = {
    "query": ParamLocation.QUERY, "path": ParamLocation.PATH, "header": ParamLocation.HEADER,
    "cookie": ParamLocation.COOKIE, "body": ParamLocation.BODY, "formData": ParamLocation.BODY,
}

# Conventional spec locations worth checking when a host is confirmed in scope.
CONVENTIONAL_SPEC_PATHS = (
    "/openapi.json", "/swagger.json", "/v2/swagger.json", "/v3/api-docs",
    "/api-docs", "/api/openapi.json", "/swagger/v1/swagger.json",
)
CONVENTIONAL_GRAPHQL_PATHS = ("/graphql", "/api/graphql", "/v1/graphql", "/query")

_GRAPHQL_BODY_RE = re.compile(r'["\']query["\']\s*:\s*["\']\s*(?:query|mutation|subscription)\b', re.IGNORECASE)


@dataclass(slots=True)
class OpenApiResult:
    host: str
    endpoints: list[Endpoint] = field(default_factory=list)
    parameters: list[Parameter] = field(default_factory=list)
    server_urls: list[str] = field(default_factory=list)
    auth_schemes: list[str] = field(default_factory=list)
    deprecated: list[str] = field(default_factory=list)
    title: str | None = None


def looks_like_openapi(data: str) -> bool:
    try:
        doc = json.loads(data)
    except (ValueError, TypeError):
        return False
    return isinstance(doc, dict) and ("openapi" in doc or "swagger" in doc) and "paths" in doc


def parse_openapi(data: str, host: str, *, source: str = "openapi") -> OpenApiResult | None:
    """Parse an OpenAPI/Swagger JSON document into endpoints and parameters."""
    try:
        doc = json.loads(data)
    except (ValueError, TypeError):
        return None
    if not isinstance(doc, dict) or "paths" not in doc:
        return None

    result = OpenApiResult(host=host)
    info = doc.get("info")
    if isinstance(info, dict):
        result.title = info.get("title")
    for server in doc.get("servers", []) or []:
        if isinstance(server, dict) and isinstance(server.get("url"), str):
            result.server_urls.append(server["url"])
    components = doc.get("components", {}) if isinstance(doc.get("components"), dict) else {}
    for scheme in (components.get("securitySchemes", {}) or {}).values():
        if isinstance(scheme, dict) and scheme.get("type"):
            result.auth_schemes.append(str(scheme.get("type")))
    for name in doc.get("securityDefinitions", {}) or {}:  # swagger 2
        result.auth_schemes.append(str(name))

    paths = doc.get("paths")
    if not isinstance(paths, dict):
        return result
    for path, item in paths.items():
        if not isinstance(item, dict):
            continue
        shared = item.get("parameters", []) if isinstance(item.get("parameters"), list) else []
        for method, op in item.items():
            if method.lower() not in _HTTP_METHODS or not isinstance(op, dict):
                continue
            endpoint = make_endpoint(host, str(path), method=method, source=source, confidence=0.95)
            param_names: list[str] = []
            for spec in (*shared, *(op.get("parameters", []) if isinstance(op.get("parameters"), list) else [])):
                if not isinstance(spec, dict) or "name" not in spec:
                    continue
                location = _PARAM_LOCATIONS.get(str(spec.get("in", "")), ParamLocation.UNKNOWN)
                param_names.append(str(spec["name"]))
                result.parameters.append(Parameter(
                    name=str(spec["name"]), location=location,
                    endpoint_identity=f"{method.upper()} {host}{endpoint.path}",
                    source=source, confidence=0.95,
                ))
            if isinstance(op.get("requestBody"), dict):
                param_names.append("<body>")
            result.endpoints.append(make_endpoint(
                host, str(path), method=method, source=source, confidence=0.95,
                param_names=tuple(dict.fromkeys(param_names)),
            ))
            if op.get("deprecated") is True:
                result.deprecated.append(f"{method.upper()} {path}")
    return result


def graphql_candidates_from_text(text: str) -> bool:
    """True when a response/JS body contains a GraphQL request structure."""
    return bool(_GRAPHQL_BODY_RE.search(text))
