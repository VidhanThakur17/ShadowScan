"""Conservative content normalization for noise reduction.

The normalized hash should ignore values that change on *every* request
(CSRF tokens, CSP nonces, request IDs, server render timestamps). It should
still change whenever the page changes in a way a human might care about.

Design rules:

* **Each rule is a small, pure ``str -> str`` function** and can be tested
  alone. :class:`ContentNormalizer` applies an ordered tuple of rules.
* **Values are replaced by fixed placeholders.** They are not deleted, so the
  page structure (which attributes exist) still affects the hash.
* **Only exact, well-known names are matched** (``csrf-token``,
  ``__VIEWSTATE``, ``data-request-id``, ...). Free text, URLs, script/style
  sources, form actions, links and cache-busting query strings are never
  touched, because changes there can matter for security, e.g. a new JS
  bundle or a new endpoint.
* The raw SHA-256 is always kept next to the normalized one, so nothing
  normalized away is lost from the record.

Known limitations: framework-specific tokens with unusual names, volatile
values in free text ("Rendered in 12 ms"), and rotating ad or recommendation
blocks are *not* normalized. Those pages still show up as content changes.
The per-asset ``change_ratio`` exists to expose such naturally dynamic pages.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass

TOKEN_PLACEHOLDER = "__SS_TOKEN__"
NONCE_PLACEHOLDER = "__SS_NONCE__"
ID_PLACEHOLDER = "__SS_ID__"
TIME_PLACEHOLDER = "__SS_TIME__"

# An attribute inside a tag: name = "value" | 'value' | bare-value
_ATTR_VALUE = r"""(?P<q>"[^"]*"|'[^']*'|[^\s"'>]+)"""
_ATTR_RE = re.compile(r"""(?P<name>[^\s=/>"']+)\s*=\s*""" + _ATTR_VALUE)
_TAG_RE = re.compile(r"<[a-zA-Z][^<>]{0,4096}>")
_META_INPUT_RE = re.compile(r"<(?:meta|input)\b[^<>]{0,4096}>", re.IGNORECASE)
_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)

# Exact (case-insensitive) names of anti-CSRF / anti-replay form and meta fields.
_TOKEN_FIELD_NAMES = frozenset({
    "csrf-token", "csrf_token", "csrftoken", "_csrf", "csrf", "_csrf_token",
    "xsrf-token", "xsrf_token", "_xsrf", "csrfmiddlewaretoken", "authenticity_token",
    "__requestverificationtoken", "_token", "__viewstate", "__viewstategenerator",
    "__eventvalidation", "form_build_id", "form_token",
})
# Names that identify a single request/trace/session, as meta names or data-* attributes.
_ID_NAME_RE = re.compile(r"^(?:data-)?(?:x-)?(?:request|req|trace|correlation|span|session)[-_]?id$", re.IGNORECASE)
# Machine-generated render-time metadata. Build/version/modified times are deliberately
# excluded: they change when something was actually deployed or edited.
_TIME_NAME_RE = re.compile(
    r"^(?:data-)?(?:timestamp|ts|server[-_]?time(?:stamp)?|render(?:ed)?[-_]?(?:at|time)|"
    r"generated[-_]?(?:at|time)?|generation[-_]?time|request[-_]?time|current[-_]?time)$",
    re.IGNORECASE,
)
# Values that look like an epoch (seconds or ms) or an ISO-8601 timestamp.
_TIME_VALUE_RE = re.compile(r"^(?:\d{9,13}(?:\.\d+)?|\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?)$")
# Opaque identifier: UUID or a long-ish token of id characters.
_ID_VALUE_RE = re.compile(r"^(?:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|[A-Za-z0-9+/=_:.-]{8,128})$")

_JSON_ID_RE = re.compile(
    r'("(?:requestId|request_id|traceId|trace_id|correlationId|correlation_id|spanId|span_id)"\s*:\s*)"[^"\\]{1,128}"'
)
_JSON_TIME_RE = re.compile(
    r'("(?:timestamp|serverTime|server_time|serverTimestamp|server_timestamp|renderedAt|rendered_at|'
    r'generatedAt|generated_at|requestTime|request_time|currentTime|current_time)"\s*:\s*)'
    r'(?:\d{9,13}(?:\.\d+)?|"\d{4}-\d{2}-\d{2}[T ][0-9:.]{5,15}(?:Z|[+-]\d{2}:?\d{2})?")'
)
_NONCE_ATTR_RE = re.compile(r"""(?<![\w-])((?:data-)?nonce\s*=\s*)(?:"[^"]*"|'[^']*'|[^\s"'>]+)""", re.IGNORECASE)
_INTER_TAG_WS_RE = re.compile(r">\s+<")
_WS_RE = re.compile(r"\s+")


def _unquote(value: str) -> str:
    return value[1:-1] if value[:1] in ("'", '"') and value[-1:] == value[:1] and len(value) >= 2 else value


def _replace_attr_value(tag: str, attr_names: frozenset[str], placeholder: str) -> str:
    """Replace the value of the given attributes (by lower-case name) inside one tag."""

    def sub(match: re.Match[str]) -> str:
        if match.group("name").lower() in attr_names:
            return f'{match.group("name")}="{placeholder}"'
        return match.group(0)

    return _ATTR_RE.sub(sub, tag)


def _attributes(tag: str) -> dict[str, str]:
    return {m.group("name").lower(): _unquote(m.group("q")) for m in _ATTR_RE.finditer(tag)}


# --- rules ---------------------------------------------------------------------------------


def strip_html_comments(text: str) -> str:
    """Remove ``<!-- ... -->`` comments. These often carry render timestamps or cache IDs."""
    return _COMMENT_RE.sub("", text)


def mask_csrf_tokens(text: str) -> str:
    """Mask the value of well-known anti-CSRF ``<meta>`` / ``<input>`` fields.

    Only fields whose ``name``/``id``/``property`` *exactly* matches a known token
    name are touched. ``<input name="role" value="admin">`` is never changed.
    """

    def sub(match: re.Match[str]) -> str:
        tag = match.group(0)
        attrs = _attributes(tag)
        names = {attrs.get(key, "").lower() for key in ("name", "id", "property")}
        if names & _TOKEN_FIELD_NAMES:
            return _replace_attr_value(tag, frozenset({"content", "value"}), TOKEN_PLACEHOLDER)
        return tag

    return _META_INPUT_RE.sub(sub, text)


def mask_nonces(text: str) -> str:
    """Mask ``nonce`` / ``data-nonce`` attribute values (CSP nonces are per-response).
    Only applied inside tags, so ``nonce=`` in visible text is left alone."""

    def tag_sub(match: re.Match[str]) -> str:
        return _NONCE_ATTR_RE.sub(lambda m: f'{m.group(1)}"{NONCE_PLACEHOLDER}"', match.group(0))

    return _TAG_RE.sub(tag_sub, text)


def mask_request_ids(text: str) -> str:
    """Mask request/trace/session identifiers in ``data-*-id`` attributes, ``<meta>``
    tags and JSON keys. The value must look like an opaque ID (UUID or token)."""

    def tag_sub(match: re.Match[str]) -> str:
        tag = match.group(0)

        def attr_sub(attr: re.Match[str]) -> str:
            name = attr.group("name")
            if _ID_NAME_RE.match(name) and _ID_VALUE_RE.match(_unquote(attr.group("q"))):
                return f'{name}="{ID_PLACEHOLDER}"'
            return attr.group(0)

        tag = _ATTR_RE.sub(attr_sub, tag)
        if tag[1:5].lower() == "meta":
            attrs = _attributes(tag)
            if _ID_NAME_RE.match(attrs.get("name", "")) and _ID_VALUE_RE.match(attrs.get("content", "")):
                tag = _replace_attr_value(tag, frozenset({"content"}), ID_PLACEHOLDER)
        return tag

    text = _TAG_RE.sub(tag_sub, text)
    return _JSON_ID_RE.sub(lambda m: f'{m.group(1)}"{ID_PLACEHOLDER}"', text)


def mask_render_timestamps(text: str) -> str:
    """Mask timestamps in machine-generated positions: ``data-timestamp``-style
    attributes, ``<meta name="generated-at">``-style tags and JSON keys such as
    ``"serverTime"``. Only epoch or ISO-8601 values are touched."""

    def tag_sub(match: re.Match[str]) -> str:
        tag = match.group(0)

        def attr_sub(attr: re.Match[str]) -> str:
            name = attr.group("name")
            if name.lower().startswith("data-") and _TIME_NAME_RE.match(name) and _TIME_VALUE_RE.match(_unquote(attr.group("q"))):
                return f'{name}="{TIME_PLACEHOLDER}"'
            return attr.group(0)

        tag = _ATTR_RE.sub(attr_sub, tag)
        if tag[1:5].lower() == "meta":
            attrs = _attributes(tag)
            if _TIME_NAME_RE.match(attrs.get("name", "")) and _TIME_VALUE_RE.match(attrs.get("content", "")):
                tag = _replace_attr_value(tag, frozenset({"content"}), TIME_PLACEHOLDER)
        return tag

    text = _TAG_RE.sub(tag_sub, text)
    return _JSON_TIME_RE.sub(lambda m: f'{m.group(1)}"{TIME_PLACEHOLDER}"', text)


def collapse_whitespace(text: str) -> str:
    """Drop whitespace between tags and collapse other runs to one space.

    This ignores re-indentation and line-ending changes. Whitespace inside
    ``<pre>`` is collapsed too; for change monitoring that trade-off is acceptable.
    """
    return _WS_RE.sub(" ", _INTER_TAG_WS_RE.sub("><", text)).strip()


NormalizationRule = Callable[[str], str]

# Order matters: comments go first (they may contain tag-like text), whitespace goes last.
DEFAULT_RULES: tuple[NormalizationRule, ...] = (
    strip_html_comments,
    mask_csrf_tokens,
    mask_nonces,
    mask_request_ids,
    mask_render_timestamps,
    collapse_whitespace,
)


@dataclass(frozen=True, slots=True)
class ContentNormalizer:
    """Applies an ordered sequence of text rules."""

    rules: Sequence[NormalizationRule] = DEFAULT_RULES

    def __call__(self, text: str) -> str:
        for rule in self.rules:
            text = rule(text)
        return text


DEFAULT_NORMALIZER = ContentNormalizer()
