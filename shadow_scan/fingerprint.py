"""Response fingerprinting.

The prober never holds a whole body. For each response it opens a
:class:`FingerprintSession`, which builds one fingerprinter per registered
factory and passes it the response metadata (:class:`ResponseInfo`).
Body chunks are then streamed into every fingerprinter. Each fingerprinter's
string value is stored in ``observation_fingerprints`` under its ``name``, so
adding a strategy needs no schema change.

Built-in strategies:

* ``raw_sha256``: :class:`RawSha256Fingerprinter`, the SHA-256 of the exact
  (decompressed) body bytes. Always kept.
* ``normalized_sha256``: :class:`NormalizedContentFingerprinter`. For
  textual responses it is the SHA-256 of the body after the conservative
  noise normalization in :mod:`normalization`, plus a similarity sketch
  (see :mod:`similarity`).

  **Binary decision:** for binary responses, ``normalized_sha256`` equals the
  raw hash, because normalization of bytes is the identity. Change detection
  can then always compare ``normalized_sha256``, and binary content never gets
  a similarity score ("not measured"). The value is ``None`` only when the body
  was truncated, or when a text body exceeds ``NORMALIZATION_MAX_BYTES``. In
  that case change detection falls back to the raw hash.

Further strategies (favicon/JS bundle hashing, header or technology
fingerprints, DOM hashing) plug in as additional factories. A fingerprinter
may expose an optional ``similarity_sketch: bytes | None`` attribute, which the
session collects after finalize.
"""

from __future__ import annotations

import hashlib
import html
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from functools import partial
from typing import Protocol

from .normalization import DEFAULT_NORMALIZER, ContentNormalizer
from .similarity import build_sketch

MAX_TITLE_LENGTH = 512
_TITLE_RE = re.compile(r"<title\b[^>]*>(.*?)</title\s*>", re.IGNORECASE | re.DOTALL)
_CHARSET_RE = re.compile(r"charset\s*=\s*[\"']?([A-Za-z0-9._:-]+)", re.IGNORECASE)

_TEXT_TYPE_MARKERS = ("text/", "json", "xml", "javascript", "ecmascript", "x-www-form-urlencoded")
_BINARY_TYPE_PREFIXES = (
    "image/", "audio/", "video/", "font/", "application/octet-stream", "application/pdf",
    "application/zip", "application/gzip", "application/x-gzip", "application/wasm",
    "application/vnd.", "application/x-protobuf", "application/grpc", "application/msword",
)


@dataclass(frozen=True, slots=True)
class ResponseInfo:
    """Response metadata, known once headers arrive and before the body is read."""

    url: str | None
    status: int | None
    content_type: str | None
    headers: Mapping[str, str] = field(default_factory=dict)


class Fingerprinter(Protocol):
    """A per-response fingerprint accumulator. One instance per response."""

    name: str

    def update(self, chunk: bytes) -> None: ...

    def finalize(self, truncated: bool) -> str | None: ...


FingerprinterFactory = Callable[[ResponseInfo], Fingerprinter]


def content_kind(content_type: str | None) -> str:
    """Classify a Content-Type as ``"text"``, ``"binary"`` or ``"unknown"`` (sniff the body)."""
    if not content_type:
        return "unknown"
    lowered = content_type.lower()
    if any(marker in lowered for marker in _TEXT_TYPE_MARKERS):
        return "text"
    if lowered.startswith(_BINARY_TYPE_PREFIXES):
        return "binary"
    return "unknown"


def looks_binary(sample: bytes) -> bool:
    """Heuristic for responses without a usable Content-Type: NUL bytes mean binary."""
    return b"\x00" in sample[:1024]


def charset_of(content_type: str | None) -> str | None:
    match = _CHARSET_RE.search(content_type or "")
    return match.group(1) if match else None


class RawSha256Fingerprinter:
    """SHA-256 of the raw (decompressed) body bytes, computed incrementally."""

    name = "raw_sha256"
    __slots__ = ("_hash",)

    def __init__(self, info: ResponseInfo | None = None) -> None:
        self._hash = hashlib.sha256()

    def update(self, chunk: bytes) -> None:
        self._hash.update(chunk)

    def finalize(self, truncated: bool) -> str | None:
        return self._hash.hexdigest()


class NormalizedContentFingerprinter:
    """SHA-256 of normalized text, plus a similarity sketch.

    Memory is bounded. Text is buffered only up to ``max_bytes``; past that the
    buffer is dropped and no normalized hash is produced. Binary responses
    are never buffered: they are hashed incrementally instead.
    """

    name = "normalized_sha256"
    __slots__ = ("_info", "_normalizer", "_max_bytes", "_sketch_max_bytes", "_divisor",
                 "_kind", "_buffer", "_overflow", "_binary_hash", "similarity_sketch")

    def __init__(
        self,
        info: ResponseInfo,
        normalizer: ContentNormalizer = DEFAULT_NORMALIZER,
        max_bytes: int = 1024 * 1024,
        sketch_max_bytes: int = 512 * 1024,
        chunk_divisor: int = 8,
    ) -> None:
        self._info = info
        self._normalizer = normalizer
        self._max_bytes = max_bytes
        self._sketch_max_bytes = sketch_max_bytes
        self._divisor = chunk_divisor
        self._kind = content_kind(info.content_type)
        self._buffer = bytearray()
        self._overflow = False
        self._binary_hash = hashlib.sha256() if self._kind == "binary" else None
        self.similarity_sketch: bytes | None = None

    def update(self, chunk: bytes) -> None:
        if self._kind == "unknown":
            # Decide once, from the first non-empty chunk.
            if looks_binary(chunk):
                self._kind = "binary"
                self._binary_hash = hashlib.sha256()
            else:
                self._kind = "text"
        if self._binary_hash is not None:
            self._binary_hash.update(chunk)
            return
        if self._overflow:
            return
        if len(self._buffer) + len(chunk) > self._max_bytes:
            self._overflow = True
            self._buffer = bytearray()
            return
        self._buffer += chunk

    def finalize(self, truncated: bool) -> str | None:
        if truncated:
            return None  # a hash of a prefix is not a trustworthy content fingerprint
        if self._binary_hash is not None:
            return self._binary_hash.hexdigest()
        if self._overflow:
            return None
        encoding = charset_of(self._info.content_type) or "utf-8"
        try:
            text = self._buffer.decode(encoding, errors="replace")
        except LookupError:
            text = self._buffer.decode("utf-8", errors="replace")
        self._buffer = bytearray()
        normalized = self._normalizer(text)
        self.similarity_sketch = build_sketch(normalized, self._sketch_max_bytes, self._divisor)
        return hashlib.sha256(normalized.encode("utf-8", "replace")).hexdigest()


@dataclass(slots=True)
class FingerprintSet:
    values: dict[str, str]
    similarity_sketch: bytes | None = None


class FingerprintSession:
    """Fans body chunks out to the fingerprinters active for one response."""

    __slots__ = ("_fingerprinters",)

    def __init__(self, fingerprinters: Sequence[Fingerprinter]) -> None:
        self._fingerprinters = fingerprinters

    def update(self, chunk: bytes) -> None:
        for fingerprinter in self._fingerprinters:
            fingerprinter.update(chunk)

    def finalize(self, truncated: bool) -> FingerprintSet:
        """May be CPU-heavy for large text bodies; callers may run it in a worker thread."""
        result = FingerprintSet(values={})
        for fingerprinter in self._fingerprinters:
            value = fingerprinter.finalize(truncated)
            if value is not None:
                result.values[fingerprinter.name] = value
            sketch = getattr(fingerprinter, "similarity_sketch", None)
            if sketch is not None and result.similarity_sketch is None:
                result.similarity_sketch = sketch
        return result


class FingerprintEngine:
    """Builds a fresh :class:`FingerprintSession` for every response."""

    def __init__(self, factories: Sequence[FingerprinterFactory] = (RawSha256Fingerprinter,)) -> None:
        if not factories:
            raise ValueError("at least one fingerprinter is required")
        self._factories = tuple(factories)

    @classmethod
    def default(
        cls,
        normalization_max_bytes: int = 1024 * 1024,
        similarity_max_bytes: int = 512 * 1024,
        chunk_divisor: int = 8,
    ) -> FingerprintEngine:
        """Raw SHA-256 plus normalized SHA-256/similarity sketch."""
        return cls((
            RawSha256Fingerprinter,
            partial(
                NormalizedContentFingerprinter,
                max_bytes=normalization_max_bytes,
                sketch_max_bytes=similarity_max_bytes,
                chunk_divisor=chunk_divisor,
            ),
        ))

    def new_session(self, info: ResponseInfo) -> FingerprintSession:
        return FingerprintSession([factory(info) for factory in self._factories])


def _looks_like_html(content_type: str | None, head: bytes) -> bool:
    if content_type:
        return "html" in content_type.lower()
    sniff = head[:1024].lstrip().lower()
    return sniff.startswith((b"<!doctype html", b"<html"))


def extract_title(head: bytes, content_type: str | None, charset: str | None = None) -> str | None:
    """Extract and clean the ``<title>`` of an HTML document head.

    Returns ``None`` for non-HTML responses or when no title element exists.
    Whitespace is collapsed and entities are unescaped so that formatting-only
    differences do not register as title changes.
    """
    if not head or not _looks_like_html(content_type, head):
        return None
    try:
        text = head.decode(charset or "utf-8", errors="replace")
    except LookupError:
        text = head.decode("utf-8", errors="replace")
    match = _TITLE_RE.search(text)
    if match is None:
        return None
    title = " ".join(html.unescape(match.group(1)).split())
    return title[:MAX_TITLE_LENGTH]
