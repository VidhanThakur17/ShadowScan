"""ShadowScan security-analysis, controlled-validation & AI-intelligence subsystem.

This package consumes the attack-surface inventory produced by :mod:`shadow_scan.recon`
and decides which items deserve security testing, performs carefully bounded,
non-destructive validation where policy allows, correlates evidence into findings,
and optionally uses an AI provider to *advise* (never to act).

Hard safety invariants enforced throughout this package:

* A testing-policy decision is required before **every** active security request.
* Active checks never run in PASSIVE_ONLY mode.
* State-changing requests are never issued automatically; they become
  manual-validation packages instead.
* Request budgets and per-host rate limits bound all active work.
* Authentication material is never stored in SQLite, never logged, and never
  sent to a host it was not configured for.
* Remote/target content is always treated as untrusted data for the AI layer;
  it never becomes privileged instructions.

There is no exploitation, brute force, credential attack, DoS, arbitrary command
execution or unrestricted fuzzing anywhere in this package, by design.
"""

from __future__ import annotations

SECURITY_SCHEMA_VERSION = 4
