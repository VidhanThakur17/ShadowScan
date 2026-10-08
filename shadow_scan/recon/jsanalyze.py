"""Static JavaScript analysis.

A layered analyzer, not a single regex pass:

1. **String-literal extraction** pulls the quoted string literals and template
   chunks out of the source. Most endpoints, hostnames and config values live
   in string literals, so working on them (rather than the raw blob) cuts
   false positives from minified identifiers and comments.
2. **Pattern classification** maps each literal to a candidate type
   (endpoint, route, hostname, config, graphql, source-map).
3. **Secret detection** is deliberately conservative: it keys off assignment
   *context* (a key-like identifier near the value) and value *shape*, and it
   rejects obvious non-secrets (hashes in filenames, base64 images, UUIDs,
   placeholders). This keeps "every long string is a secret" from happening.

No JavaScript is executed. Parsing is pure string work over the stdlib, so no
third-party parser dependency is introduced. If a future version wants a real
AST, :func:`extract_string_literals` is the seam to replace.

Evidence stored per finding is a short slice of surrounding text, never the
whole file.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator

from .models import FindingType, JsFinding

_MAX_FINDINGS = 2000            # bound output per file; huge bundles can't explode the DB
_EVIDENCE_WINDOW = 60

# --- layer 1: string literals ----------------------------------------------------------

_STRING_LITERAL_RE = re.compile(
    r"""(?P<q>["'`])(?P<body>(?:\\.|(?!\1)[^\\])*?)(?P=q)""",
    re.DOTALL,
)


def extract_string_literals(source: str) -> Iterator[tuple[str, int]]:
    """Yield ``(literal_value, offset)`` for each JS string/template literal."""
    for match in _STRING_LITERAL_RE.finditer(source):
        body = match.group("body")
        if "\n" in body and match.group("q") != "`":
            continue  # unterminated/garbage; template literals may span lines
        try:
            value = body.encode().decode("unicode_escape", errors="replace")
        except (UnicodeDecodeError, ValueError):
            value = body
        yield value, match.start()


# --- layer 2: pattern classification ---------------------------------------------------

_ENDPOINT_PATH_RE = re.compile(r"^/(?:[A-Za-z0-9._~%\-]+)(?:/[A-Za-z0-9._~%${}:\-]+)*/?$")
_ABS_URL_RE = re.compile(r"^(?:https?:)?//[A-Za-z0-9.\-]+(?::\d+)?(?:/\S*)?$", re.IGNORECASE)
_WS_URL_RE = re.compile(r"^wss?://[A-Za-z0-9.\-]+(?::\d+)?(?:/\S*)?$", re.IGNORECASE)
_HOSTNAME_RE = re.compile(r"^(?=.{4,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}$")
_SOURCE_MAP_RE = re.compile(r"//[#@]\s*sourceMappingURL=(\S+)")
_GRAPHQL_HINT_RE = re.compile(r"/graphql\b|ApolloClient|__APOLLO|gql`|InMemoryCache|graphql-tag", re.IGNORECASE)
_API_HINT_RE = re.compile(r"/(?:api|rest|graphql|v\d|internal|admin|auth|oauth|debug|export|download|upload)\b", re.IGNORECASE)
_PARAM_IN_PATH_RE = re.compile(r"[?&]([A-Za-z_][A-Za-z0-9_]{0,40})=")
_CONFIG_KEY_RE = re.compile(
    r"\b(apiUrl|api_base|baseUrl|base_url|endpoint|bucket|s3Bucket|gcsBucket|region|"
    r"featureFlag|feature_flags?|environment|env|config|clientId|client_id|tenant|realm)\b",
    re.IGNORECASE,
)
_BUCKET_RE = re.compile(
    r"^(?:https?://)?(?:[A-Za-z0-9.\-]+\.s3[.\-][A-Za-z0-9.\-]*amazonaws\.com"
    r"|[A-Za-z0-9.\-]+\.storage\.googleapis\.com"
    r"|storage\.googleapis\.com/[A-Za-z0-9.\-]+"
    r"|[A-Za-z0-9.\-]+\.blob\.core\.windows\.net)",
    re.IGNORECASE,
)

# --- layer 3: conservative secrets -----------------------------------------------------

_SECRET_KEY_RE = re.compile(
    r"\b([A-Za-z0-9_]*(?:secret|api[_-]?key|apikey|access[_-]?key|token|passwd|password|"
    r"private[_-]?key|client[_-]?secret|auth[_-]?token|bearer)[A-Za-z0-9_]*)\b"
    r"\s*[:=]\s*(?P<q>[\"'])(?P<val>[^\"']{8,120})(?P=q)",
    re.IGNORECASE,
)
# High-signal provider token shapes that stand on their own (no context needed).
_KNOWN_TOKEN_RES = (
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),                        # AWS access key id
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),             # GitHub token
    re.compile(r"\bsk_live_[0-9a-zA-Z]{24,}\b"),               # Stripe secret key
    re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),                 # Google API key
    re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b"),          # Slack token
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"),
)
# Values that look long but are not secrets.
_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)
_HEXHASH_RE = re.compile(r"^[0-9a-f]{8,64}$", re.IGNORECASE)
_PLACEHOLDER_RE = re.compile(
    r"(?:your|example|placeholder|dummy|test|sample|xxx+|changeme|redacted|<[^>]+>|\{\{?[^}]+\}?\}|%[sd]|\$\{)",
    re.IGNORECASE,
)


def _evidence(source: str, offset: int) -> str:
    start = max(0, offset - _EVIDENCE_WINDOW // 2)
    snippet = source[start:start + _EVIDENCE_WINDOW]
    return " ".join(snippet.split())


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    from math import log2
    counts = {c: value.count(c) for c in set(value)}
    n = len(value)
    return -sum((c / n) * log2(c / n) for c in counts.values())


def is_probable_secret(value: str) -> bool:
    """Shape-based filter: reject obvious non-secrets, require entropy/charset variety."""
    v = value.strip()
    if len(v) < 8 or len(v) > 200:
        return False
    if _PLACEHOLDER_RE.search(v) or _UUID_RE.match(v):
        return False
    if _HEXHASH_RE.match(v) and len(v) <= 40:
        return False  # asset hash / short digest
    if v.count("/") >= 2 or v.startswith(("/", "./", "../", "http")):
        return False  # a path or URL, not a secret
    if " " in v:
        return False
    classes = sum(bool(re.search(p, v)) for p in (r"[a-z]", r"[A-Z]", r"[0-9]", r"[^A-Za-z0-9]"))
    return classes >= 3 and _shannon_entropy(v) >= 3.2


def _classify_literal(value: str) -> JsFinding | None:
    v = value.strip()
    if not v or len(v) > 400:
        return None
    if _WS_URL_RE.match(v):
        return JsFinding(FindingType.ENDPOINT_CANDIDATE, v, 0.8)
    if _BUCKET_RE.match(v):
        return JsFinding(FindingType.CONFIG_REFERENCE, v, 0.7)
    if _ABS_URL_RE.match(v):
        return JsFinding(FindingType.HOSTNAME_CANDIDATE, v, 0.6)
    path_part = v.split("?", 1)[0].split("#", 1)[0]
    if path_part.startswith("/") and _ENDPOINT_PATH_RE.match(path_part) and ("/" in path_part[1:] or _API_HINT_RE.search(v)):
        is_api = bool(_API_HINT_RE.search(v))
        kind = FindingType.ENDPOINT_CANDIDATE if is_api else FindingType.ROUTE_CANDIDATE
        return JsFinding(kind, v, 0.85 if is_api else 0.5)
    if _HOSTNAME_RE.match(v):
        return JsFinding(FindingType.HOSTNAME_CANDIDATE, v, 0.5)
    return None


def analyze_js(source: str, *, source_url: str | None = None) -> list[JsFinding]:
    """Return classified, de-duplicated findings for one JavaScript file."""
    findings: list[JsFinding] = []
    seen: set[tuple[str, str]] = set()

    def add(finding: JsFinding) -> None:
        key = (finding.finding_type.value, finding.value)
        if key not in seen and len(findings) < _MAX_FINDINGS:
            seen.add(key)
            findings.append(finding)

    # Source maps (operate on raw source: these are comments, not literals).
    for match in _SOURCE_MAP_RE.finditer(source):
        add(JsFinding(FindingType.SOURCE_MAP, match.group(1).strip(), 0.95, _evidence(source, match.start())))

    # Known high-signal tokens anywhere in the source.
    for token_re in _KNOWN_TOKEN_RES:
        for match in token_re.finditer(source):
            add(JsFinding(FindingType.SECRET_CANDIDATE, match.group(0), 0.9, _evidence(source, match.start())))

    # Context-based secrets: key-like identifier assigned a secret-shaped value.
    for match in _SECRET_KEY_RE.finditer(source):
        value = match.group("val")
        if is_probable_secret(value):
            add(JsFinding(FindingType.SECRET_CANDIDATE, value, 0.65, _evidence(source, match.start())))

    # GraphQL hints.
    if _GRAPHQL_HINT_RE.search(source):
        add(JsFinding(FindingType.GRAPHQL_CANDIDATE, "/graphql", 0.6, "graphql client reference in bundle"))

    # String-literal driven candidates.
    for value, offset in extract_string_literals(source):
        if _CONFIG_KEY_RE.search(value):
            add(JsFinding(FindingType.CONFIG_REFERENCE, value.strip()[:200], 0.6, _evidence(source, offset)))
        finding = _classify_literal(value)
        if finding is not None:
            add(JsFinding(finding.finding_type, finding.value, finding.confidence, _evidence(source, offset)))
        for param_match in _PARAM_IN_PATH_RE.finditer(value):
            add(JsFinding(FindingType.PARAMETER_CANDIDATE, param_match.group(1), 0.5))

    return findings


def source_map_references(findings: Iterable[JsFinding]) -> list[str]:
    return [f.value for f in findings if f.finding_type is FindingType.SOURCE_MAP]


def companion_source_map_url(js_url: str) -> str:
    """Straightforward ``<file>.js`` -> ``<file>.js.map`` companion candidate."""
    base = js_url.split("?", 1)[0].split("#", 1)[0]
    return base + ".map"


# --- source-map content analysis -------------------------------------------------------


def analyze_source_map(data: str) -> list[JsFinding]:
    """Extract source filenames and API-looking strings from a parsed source map."""
    import json

    findings: list[JsFinding] = []
    seen: set[str] = set()

    def add(ft: FindingType, value: str, confidence: float) -> None:
        if value and value not in seen and len(findings) < _MAX_FINDINGS:
            seen.add(value)
            findings.append(JsFinding(ft, value, confidence, "source map"))

    try:
        doc = json.loads(data)
    except (ValueError, TypeError):
        return findings
    for name in doc.get("sources", []) or []:
        if isinstance(name, str):
            add(FindingType.CONFIG_REFERENCE, name.strip()[:200], 0.6)
    for content in doc.get("sourcesContent", []) or []:
        if not isinstance(content, str):
            continue
        for value, _ in extract_string_literals(content):
            finding = _classify_literal(value)
            if finding is not None and finding.finding_type in (
                FindingType.ENDPOINT_CANDIDATE, FindingType.ROUTE_CANDIDATE
            ):
                add(finding.finding_type, finding.value, finding.confidence)
    return findings
