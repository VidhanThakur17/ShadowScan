"""Deterministic security classification of endpoints and parameters.

These classifications describe *likely security relevance* to prioritize review.
They never imply a vulnerability. Classification is evidence-first: path tokens,
method and parameter names only.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from .models import EndpointClass, EndpointInfo, ParamClass

# --- endpoint classification -----------------------------------------------------------

_ENDPOINT_RULES: tuple[tuple[EndpointClass, re.Pattern[str]], ...] = (
    (EndpointClass.API_DOCUMENTATION, re.compile(r"/(?:openapi|swagger|api-docs|v\d/api-docs)(?:\.json|\.yaml)?$", re.I)),
    (EndpointClass.GRAPHQL, re.compile(r"/graphql\b|/gql\b", re.I)),
    (EndpointClass.AUTHENTICATION, re.compile(r"/(?:login|logout|signin|signout|register|signup|auth|oauth|token|"
                                              r"refresh|session|password|forgot|reset|otp|mfa|2fa|verify)\b", re.I)),
    (EndpointClass.ADMINISTRATIVE, re.compile(r"/(?:admin|administrator|manage|management|console|internal|backoffice|root)\b", re.I)),
    (EndpointClass.DEBUG_INTERNAL, re.compile(r"/(?:debug|trace|_debug|actuator|metrics|health|status|env|config|phpinfo|__internal)\b", re.I)),
    (EndpointClass.PAYMENT_BILLING, re.compile(r"/(?:payment|billing|invoice|charge|checkout|subscription|refund|wallet|card)\b", re.I)),
    (EndpointClass.IMPORT_UPLOAD, re.compile(r"/(?:upload|import|ingest)\b", re.I)),
    (EndpointClass.EXPORT_DOWNLOAD, re.compile(r"/(?:export|download|report|backup|dump)\b", re.I)),
    (EndpointClass.FILE_HANDLING, re.compile(r"/(?:file|files|document|documents|attachment|media|image|asset)\b", re.I)),
    (EndpointClass.USER_MANAGEMENT, re.compile(r"/(?:users?|accounts?|profiles?|members?|tenants?|organizations?|orgs?)\b", re.I)),
    (EndpointClass.REDIRECT_NAVIGATION, re.compile(r"/(?:redirect|goto|go|out|link|forward|continue|return)\b", re.I)),
    (EndpointClass.SEARCH_QUERY, re.compile(r"/(?:search|query|find|lookup|filter)\b", re.I)),
    (EndpointClass.WEBHOOK_CALLBACK, re.compile(r"/(?:webhook|callback|hook|notify|event)s?\b", re.I)),
)


def classify_endpoint(endpoint: EndpointInfo) -> list[EndpointClass]:
    """Return the security-relevant classes for an endpoint (may be several)."""
    path = endpoint.path
    classes: list[EndpointClass] = []
    for cls, pattern in _ENDPOINT_RULES:
        if pattern.search(path) and cls not in classes:
            classes.append(cls)
    # Parameter-driven hints.
    params = {p.lower() for p in endpoint.param_names}
    if params & {"role", "is_admin", "permission", "scope"} and EndpointClass.AUTHORIZATION not in classes:
        classes.append(EndpointClass.AUTHORIZATION)
    if not classes:
        classes.append(EndpointClass.GENERIC)
    return classes


# --- parameter classification ----------------------------------------------------------

_OBJECT_ID = {"id", "user_id", "userid", "account_id", "accountid", "order_id", "tenant_id",
              "client_id", "org_id", "orgid", "uid", "object_id", "record_id", "item_id", "doc_id"}
_ACCESS_CONTROL = {"role", "roles", "permission", "permissions", "admin", "is_admin", "isadmin",
                   "group", "groups", "scope", "scopes", "privilege", "acl"}
_REDIRECT_SSRF = {"url", "uri", "redirect", "redirect_uri", "redirecturl", "callback", "next",
                  "return", "returnurl", "return_url", "dest", "destination", "continue", "webhook", "host", "target", "link", "goto", "forward"}
_FILE_PATH = {"file", "filename", "path", "folder", "dir", "template", "download", "upload",
              "document", "attachment", "src", "source", "page", "include"}
_QUERY_INJECTION = {"query", "q", "search", "filter", "sort", "order", "command", "cmd",
                    "expression", "expr", "exec", "eval", "code", "sql"}
_AUTHENTICATION = {"token", "otp", "code", "password", "passwd", "pwd", "session", "sessionid",
                   "jwt", "api_key", "apikey", "access_token", "refresh_token", "secret", "auth", "bearer"}

_PARAM_FAMILIES: tuple[tuple[ParamClass, set[str]], ...] = (
    (ParamClass.ACCESS_CONTROL, _ACCESS_CONTROL),
    (ParamClass.AUTHENTICATION, _AUTHENTICATION),
    (ParamClass.REDIRECT_SSRF, _REDIRECT_SSRF),
    (ParamClass.FILE_PATH, _FILE_PATH),
    (ParamClass.OBJECT_IDENTIFIER, _OBJECT_ID),
    (ParamClass.QUERY_INJECTION, _QUERY_INJECTION),
)
_ID_SUFFIX_RE = re.compile(r"(?:^|_)(id)$", re.I)


def classify_parameter(name: str) -> ParamClass:
    """Classify a single parameter name into a security-relevant family."""
    lowered = name.lower().strip()
    for family, names in _PARAM_FAMILIES:
        if lowered in names:
            return family
    if _ID_SUFFIX_RE.search(lowered):
        return ParamClass.OBJECT_IDENTIFIER
    return ParamClass.GENERIC


def classify_parameters(names: Iterable[str]) -> dict[str, ParamClass]:
    return {name: classify_parameter(name) for name in names}


# Parameter families that raise review relevance (never a vulnerability claim).
_RELEVANT = {ParamClass.OBJECT_IDENTIFIER, ParamClass.ACCESS_CONTROL, ParamClass.REDIRECT_SSRF,
             ParamClass.FILE_PATH, ParamClass.QUERY_INJECTION, ParamClass.AUTHENTICATION}


def relevance_score(endpoint: EndpointInfo) -> int:
    """A small 0-100 relevance bump from classification, for prioritization only."""
    classes = classify_endpoint(endpoint)
    weights = {
        EndpointClass.ADMINISTRATIVE: 30, EndpointClass.AUTHORIZATION: 28,
        EndpointClass.AUTHENTICATION: 22, EndpointClass.PAYMENT_BILLING: 26,
        EndpointClass.DEBUG_INTERNAL: 24, EndpointClass.IMPORT_UPLOAD: 20,
        EndpointClass.EXPORT_DOWNLOAD: 16, EndpointClass.USER_MANAGEMENT: 16,
        EndpointClass.FILE_HANDLING: 14, EndpointClass.REDIRECT_NAVIGATION: 14,
        EndpointClass.GRAPHQL: 12, EndpointClass.WEBHOOK_CALLBACK: 12,
        EndpointClass.API_DOCUMENTATION: 10, EndpointClass.SEARCH_QUERY: 8,
        EndpointClass.GENERIC: 0,
    }
    base = max((weights.get(c, 0) for c in classes), default=0)
    param_bonus = sum(6 for p in endpoint.param_names if classify_parameter(p) in _RELEVANT)
    return min(100, base + min(param_bonus, 30))
