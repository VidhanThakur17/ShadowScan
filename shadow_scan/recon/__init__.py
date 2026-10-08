"""ShadowScan recon & attack-surface mapping subsystem.

This package turns ShadowScan from a change monitor into a persistent
attack-surface intelligence system. It is layered on top of the existing
monitoring engine (``shadow_scan``) and reuses its HTTP probing, fingerprints,
scoring and single-writer SQLite design rather than duplicating them.

Everything here is bounded and intended for *authorized* bug-bounty recon:
passive discovery, DNS, bounded service/URL discovery, safe crawling, static
JavaScript analysis and deterministic correlation. No exploitation, brute
force, credential attacks, fuzzing, payload injection or DoS behaviour lives
in this package, by design.
"""

from __future__ import annotations

__all__ = ["RECON_SCHEMA_VERSION"]

# Bumped when recon tables change; the monitoring schema version lives in database.py.
RECON_SCHEMA_VERSION = 3
