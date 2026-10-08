"""Finding construction, secret redaction, and deduplication.

Findings from different sources (a passive monitor observation, a SAFE_ACTIVE
check, Nuclei) that describe the same issue collapse to one finding with
multiple evidence entries, keyed by ``(host, endpoint, parameter, category)``.
Evidence is redacted of obvious secrets before storage/display and is always
bounded in size.
"""

from __future__ import annotations

import hashlib
import re

from .models import Evidence, Finding

_MAX_EXCERPT = 512

# Patterns for obvious secrets to redact from stored/displayed evidence.
_REDACT_RES: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)\b(?:bearer\s+)[A-Za-z0-9._\-]{12,}"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bsk_live_[0-9a-zA-Z]{16,}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{6,}"),  # JWT
    # key[:=]value, tolerating quotes around the key and value (JSON or query style).
    re.compile(r"(?i)(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?key|token|authorization)"
               r"[\"']?\s*[:=]\s*[\"']?[^\s,;&\"']{4,}"),
)
_REDACTION = "[REDACTED]"


def redact(text: str) -> str:
    """Replace obvious secret material with a placeholder."""
    if not text:
        return text
    out = text
    for pattern in _REDACT_RES:
        out = pattern.sub(_REDACTION, out)
    return out


def redact_headers(headers: dict[str, str]) -> dict[str, str]:
    """Redact sensitive request/response headers by name and value."""
    sensitive = {"authorization", "cookie", "set-cookie", "proxy-authorization", "x-api-key"}
    out: dict[str, str] = {}
    for key, value in headers.items():
        if key.lower() in sensitive:
            out[key] = _REDACTION
        else:
            out[key] = redact(value)[:_MAX_EXCERPT]
    return out


def excerpt(body: str, limit: int = _MAX_EXCERPT) -> str:
    """A short, redacted excerpt of a response body (never the whole body)."""
    return redact(body[:limit])


def make_evidence(kind: str, summary: str, *, data: dict | None = None, source: str | None = None) -> Evidence:
    cleaned = {}
    for key, value in (data or {}).items():
        if isinstance(value, str):
            cleaned[key] = redact(value)[:_MAX_EXCERPT]
        elif isinstance(value, dict):
            cleaned[key] = {k: (redact(v)[:_MAX_EXCERPT] if isinstance(v, str) else v) for k, v in value.items()}
        else:
            cleaned[key] = value
    return Evidence(kind=kind, summary=redact(summary)[:_MAX_EXCERPT], data=cleaned, source=source)


def dedup_key(host: str, category: str, endpoint: str | None, parameter: str | None) -> str:
    raw = "|".join([host.lower(), category, (endpoint or "").lower(), (parameter or "").lower()])
    return hashlib.sha256(raw.encode()).hexdigest()[:24]


def finalize(finding: Finding) -> Finding:
    """Compute the dedup key for a finding if not already set."""
    if not finding.dedup_key:
        finding.dedup_key = dedup_key(finding.asset, finding.category, finding.endpoint, finding.parameter)
    return finding


def merge(existing: Finding, incoming: Finding) -> Finding:
    """Merge a duplicate into an existing finding: union evidence, keep best confidence/priority."""
    sources = ",".join(dict.fromkeys([*existing.source.split(","), *incoming.source.split(",")]))
    existing.source = sources
    existing.confidence = max(existing.confidence, incoming.confidence)
    existing.review_priority = max(existing.review_priority, incoming.review_priority)
    # Keep the stronger validation state.
    order = ["observed", "suspected", "manual_validation_required", "validated_non_destructively"]
    if order.index(incoming.validation_state.value) > order.index(existing.validation_state.value):
        existing.validation_state = incoming.validation_state
    seen = {(e.kind, e.summary) for e in existing.evidence}
    for e in incoming.evidence:
        if (e.kind, e.summary) not in seen:
            existing.evidence.append(e)
            seen.add((e.kind, e.summary))
    return existing


def deduplicate(findings: list[Finding]) -> list[Finding]:
    """Collapse findings sharing a dedup key, preserving multiple evidence sources."""
    merged: dict[str, Finding] = {}
    for finding in findings:
        finalize(finding)
        existing = merged.get(finding.dedup_key)
        if existing is None:
            merged[finding.dedup_key] = finding
        else:
            merge(existing, finding)
    return list(merged.values())
