"""Favicon fingerprinting (passive, bounded).

Derives favicon URL candidates from a crawled page and computes a SHA-256 over
the bounded favicon bytes. No external fingerprint database is consulted. A
changed favicon is a lightweight signal for a newly deployed or cloned
application, surfaced for review only.
"""

from __future__ import annotations

import hashlib
from urllib.parse import urlsplit, urlunsplit

from .crawler import CrawlPage
from .urls import normalize_url

MAX_FAVICON_BYTES = 256 * 1024
_ICON_RELS = ("icon", "shortcut icon", "apple-touch-icon", "mask-icon")


def favicon_candidates(page: CrawlPage) -> list[str]:
    """Candidate favicon URLs: declared ``<link rel=icon>`` first, then ``/favicon.ico``."""
    candidates: list[str] = []
    for rel, href in page.link_tags:
        if any(marker in rel for marker in _ICON_RELS):
            resolved = normalize_url(href, base=page.final_url)
            if resolved:
                candidates.append(resolved)
    try:
        parts = urlsplit(page.final_url)
        if parts.scheme and parts.netloc:
            candidates.append(urlunsplit((parts.scheme, parts.netloc, "/favicon.ico", "", "")))
    except ValueError:
        pass
    # Preserve order, drop duplicates.
    return list(dict.fromkeys(candidates))


def favicon_sha256(body: bytes) -> str | None:
    """SHA-256 of favicon bytes, or ``None`` for an empty body."""
    if not body:
        return None
    return hashlib.sha256(body[:MAX_FAVICON_BYTES]).hexdigest()
