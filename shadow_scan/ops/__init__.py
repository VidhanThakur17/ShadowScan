"""ShadowScan continuous-operations layer.

Turns ShadowScan into a daily platform: program workspaces, a unified run
command, incremental/change-aware execution, scheduling, run locking, crash
recovery/retry, notifications, reporting, the researcher feedback loop
(feedback/ignore/baseline), finding lifecycle + regression detection, database
maintenance/backup/export/import, a lightweight schema-migration framework, and
production guardrails.

Everything here orchestrates and persists around the existing monitoring,
recon and security-analysis subsystems; it does not reimplement them, and it
preserves scope enforcement, policy enforcement and the single SQLite writer.
No exploitation, no automatic report submission.
"""

from __future__ import annotations

OPS_SCHEMA_VERSION = 1
