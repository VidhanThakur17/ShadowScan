"""Bounded content similarity for textual responses.

Bodies are never stored, so similarity is measured between compact *sketches*:

1. The normalized text is split into tokens (whole tags or whitespace-separated words).
2. Tokens are grouped into chunks with *content-defined* boundaries. A chunk
   ends after any token whose CRC32 is divisible by ``chunk_divisor``, so on
   average a chunk holds ``chunk_divisor`` tokens. Because the boundaries
   depend on the content and not on position, an insertion only disturbs the
   chunks around it instead of shifting every chunk after it.
3. Each chunk becomes a 32-bit CRC. The sketch is the packed sequence of chunk
   hashes, about 4 bytes per ``chunk_divisor`` tokens.

Similarity is ``difflib.SequenceMatcher.quick_ratio()`` over the two chunk
sequences: ``2 * matches / total`` on the multiset of chunks, in O(n). 1.0
means effectively identical and 0.0 means nothing in common. It measures
*how much* changed, not *where*, and it does not notice pure reordering of
chunks.

Texts larger than ``max_bytes`` get no sketch. Similarity is then reported as
"not measured" instead of being estimated from a partial prefix, which could
hide a change made after the prefix.
"""

from __future__ import annotations

import difflib
import re
import sys
import zlib
from array import array

_TOKEN_RE = re.compile(r"<[^<>]{0,512}>|[^\s<]+")


def build_sketch(text: str, max_bytes: int, chunk_divisor: int = 8) -> bytes | None:
    """Return the packed sketch of ``text``, or ``None`` when it exceeds ``max_bytes``."""
    if len(text) > max_bytes:  # characters >= bytes/4; cheap pre-check before encoding
        return None
    if len(text.encode("utf-8", "replace")) > max_bytes:
        return None
    chunks = array("I")
    current = 0
    pending = False
    crc32 = zlib.crc32
    for token in _TOKEN_RE.findall(text):
        data = token.encode("utf-8", "replace")
        current = crc32(data, current)
        pending = True
        if crc32(data) % chunk_divisor == 0:
            chunks.append(current)
            current = 0
            pending = False
    if pending:
        chunks.append(current)
    if sys.byteorder == "big":
        chunks.byteswap()
    return chunks.tobytes()


def _unpack(sketch: bytes) -> list[int]:
    values = array("I")
    values.frombytes(sketch)
    if sys.byteorder == "big":
        values.byteswap()
    return values.tolist()


def sketch_similarity(a: bytes, b: bytes) -> float:
    """Similarity in [0.0, 1.0] between two sketches from :func:`build_sketch`."""
    if a == b:
        return 1.0
    left, right = _unpack(a), _unpack(b)
    if not left or not right:
        return 0.0
    ratio = difflib.SequenceMatcher(None, left, right, autojunk=False).quick_ratio()
    return round(ratio, 4)
