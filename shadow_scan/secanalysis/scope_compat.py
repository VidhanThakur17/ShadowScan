"""Small helper to build a recon :class:`ScopeEngine` from scope lines.

Security analysis reuses the recon scope engine rather than defining a second
scope model; this is just a convenience wrapper.
"""

from __future__ import annotations

from ..recon.scope import ScopeEngine


def build_scope(lines: list[str], *, probe_unknown: bool = False) -> ScopeEngine:
    return ScopeEngine.parse(lines, probe_unknown=probe_unknown)
