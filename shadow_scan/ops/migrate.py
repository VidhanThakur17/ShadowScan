"""Lightweight, ordered, transactional schema-migration framework.

From this milestone on, historical data is valuable: databases are migrated,
never deleted. The framework coexists with the existing per-subsystem schema
initializers (monitoring ``user_version``, ``recon_meta``, ``sec_meta``), which
remain the source of truth for those tables. Migrations here own the *ops*
tables and any cross-cutting upgrades.

Each migration is ``(id, description, apply_fn)`` where ``id`` is a
monotonically increasing integer. Applied ids are recorded in
``schema_migrations``. Applying is transactional per migration: a failure rolls
that migration back and stops, leaving earlier migrations intact. Re-running is
idempotent (applied ids are skipped, and every migration uses
``CREATE ... IF NOT EXISTS``).
"""

from __future__ import annotations

import logging
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass

from ..database import Database

logger = logging.getLogger(__name__)

MigrationFn = Callable[[sqlite3.Connection], None]


@dataclass(frozen=True, slots=True)
class Migration:
    id: int
    description: str
    apply: MigrationFn


def _exec_script(conn: sqlite3.Connection, script: str) -> None:
    """Execute statements individually so we stay inside the caller's transaction
    (``executescript`` would issue an implicit COMMIT and break atomicity)."""
    # Drop full-line SQL comments first (they may contain ';', which would break the split).
    code = "\n".join(line for line in script.splitlines() if not line.strip().startswith("--"))
    for statement in code.split(";"):
        stmt = statement.strip()
        if stmt:
            conn.execute(stmt)


def _m0001_ops_tables(conn: sqlite3.Connection) -> None:
    _exec_script(conn, _OPS_SCHEMA)


_OPS_SCHEMA = """
CREATE TABLE IF NOT EXISTS ops_runs (
    id INTEGER PRIMARY KEY, program TEXT NOT NULL, started_at TEXT NOT NULL,
    finished_at TEXT, status TEXT NOT NULL, stages_json TEXT NOT NULL DEFAULT '{}',
    summary_json TEXT, pid INTEGER, host TEXT
);
CREATE INDEX IF NOT EXISTS idx_ops_runs_program ON ops_runs(program, id DESC);

-- Incremental execution: evidence fingerprints per object, so unchanged work is skipped.
CREATE TABLE IF NOT EXISTS ops_fingerprints (
    object_type TEXT NOT NULL, object_key TEXT NOT NULL, fingerprint TEXT NOT NULL,
    updated_at TEXT NOT NULL, PRIMARY KEY (object_type, object_key)
) WITHOUT ROWID;

-- Researcher feedback (deterministic ranking signal; never ML, never overrides policy).
CREATE TABLE IF NOT EXISTS ops_feedback (
    id INTEGER PRIMARY KEY, program TEXT NOT NULL, target_kind TEXT NOT NULL,
    target_key TEXT NOT NULL, verdict TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ops_feedback ON ops_feedback(program, target_kind, target_key);

-- Program-scoped ignore rules (suppress noise; never delete evidence).
CREATE TABLE IF NOT EXISTS ops_ignore_rules (
    id INTEGER PRIMARY KEY, program TEXT NOT NULL, rule_type TEXT NOT NULL,
    pattern TEXT NOT NULL, note TEXT, created_at TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_ops_ignore ON ops_ignore_rules(program, active);

-- Explicit baselines ("this normally changes / 403 is expected").
CREATE TABLE IF NOT EXISTS ops_baselines (
    id INTEGER PRIMARY KEY, program TEXT NOT NULL, scope_kind TEXT NOT NULL,
    scope_key TEXT NOT NULL, expectation TEXT NOT NULL, note TEXT, created_at TEXT NOT NULL,
    UNIQUE (program, scope_kind, scope_key, expectation)
);

-- Finding lifecycle: status with full non-destructive timeline + lineage.
CREATE TABLE IF NOT EXISTS ops_finding_state (
    dedup_key TEXT PRIMARY KEY, program TEXT NOT NULL, lifecycle TEXT NOT NULL DEFAULT 'new',
    lineage_key TEXT, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
    resolved_at TEXT, regressed_count INTEGER NOT NULL DEFAULT 0
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS idx_ops_finding_state_prog ON ops_finding_state(program, lifecycle);

CREATE TABLE IF NOT EXISTS ops_finding_timeline (
    id INTEGER PRIMARY KEY, dedup_key TEXT NOT NULL, event TEXT NOT NULL,
    detail TEXT, created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ops_timeline ON ops_finding_timeline(dedup_key, id);

-- Timestamped notes attached to assets/endpoints/review items/findings.
CREATE TABLE IF NOT EXISTS ops_notes (
    id INTEGER PRIMARY KEY, program TEXT NOT NULL, target_kind TEXT NOT NULL,
    target_key TEXT NOT NULL, note TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ops_notes ON ops_notes(program, target_kind, target_key);

-- Notification dedup ledger (never re-alert on an unchanged event).
CREATE TABLE IF NOT EXISTS ops_notifications (
    id INTEGER PRIMARY KEY, program TEXT NOT NULL, event_type TEXT NOT NULL,
    dedup_key TEXT NOT NULL, priority INTEGER NOT NULL DEFAULT 0, sent_at TEXT NOT NULL,
    UNIQUE (program, dedup_key)
);

-- External tool health.
CREATE TABLE IF NOT EXISTS ops_tool_health (
    tool TEXT PRIMARY KEY, version TEXT, available INTEGER NOT NULL DEFAULT 0,
    last_success TEXT, last_error TEXT, timeouts INTEGER NOT NULL DEFAULT 0,
    parse_failures INTEGER NOT NULL DEFAULT 0, updated_at TEXT NOT NULL
) WITHOUT ROWID;

-- Per-run performance metrics (lightweight; no external observability framework).
CREATE TABLE IF NOT EXISTS ops_metrics (
    id INTEGER PRIMARY KEY, run_id INTEGER, stage TEXT, metric TEXT NOT NULL,
    value REAL NOT NULL, created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ops_metrics_run ON ops_metrics(run_id);

-- AI operational feedback (useful/not_useful/incorrect) keyed by evidence fingerprint.
CREATE TABLE IF NOT EXISTS ops_ai_feedback (
    id INTEGER PRIMARY KEY, program TEXT NOT NULL, evidence_fingerprint TEXT NOT NULL,
    provider TEXT, verdict TEXT NOT NULL, created_at TEXT NOT NULL
);
"""

# Ordered migration registry. Append new migrations; never edit applied ones.
MIGRATIONS: tuple[Migration, ...] = (
    Migration(1, "ops tables (runs, fingerprints, feedback, ignore, baselines, lifecycle, notes, "
                 "notifications, tool health, metrics, ai feedback)", _m0001_ops_tables),
)


def _ensure_table(conn: sqlite3.Connection) -> None:
    conn.execute(
        "CREATE TABLE IF NOT EXISTS schema_migrations ("
        " id INTEGER PRIMARY KEY, description TEXT NOT NULL, applied_at TEXT NOT NULL)"
    )


def applied_ids(conn: sqlite3.Connection) -> set[int]:
    _ensure_table(conn)
    return {row[0] for row in conn.execute("SELECT id FROM schema_migrations")}


def pending(conn: sqlite3.Connection) -> list[Migration]:
    done = applied_ids(conn)
    return [m for m in sorted(MIGRATIONS, key=lambda m: m.id) if m.id not in done]


def migrate(database: Database, now: str) -> list[int]:
    """Apply all pending migrations in order, transactionally. Returns applied ids.

    A failing migration is rolled back and re-raised; earlier ones stay applied,
    so a later rerun resumes from the failure point.
    """
    conn = database.conn
    _ensure_table(conn)
    applied: list[int] = []
    for migration in pending(conn):
        conn.execute("BEGIN IMMEDIATE")
        try:
            migration.apply(conn)
            conn.execute("INSERT INTO schema_migrations (id, description, applied_at) VALUES (?, ?, ?)",
                         (migration.id, migration.description, now))
        except BaseException:
            conn.execute("ROLLBACK")
            logger.exception("Migration %d (%s) failed; rolled back", migration.id, migration.description)
            raise
        conn.execute("COMMIT")
        applied.append(migration.id)
        logger.info("Applied migration %d: %s", migration.id, migration.description)
    return applied


def current_version(conn: sqlite3.Connection) -> int:
    ids = applied_ids(conn)
    return max(ids) if ids else 0
