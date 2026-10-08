"""Accessor for the ops tables (created by the migration framework).

Single-writer: all methods run on the one Database connection/thread, inside a
surrounding ``database.transaction()`` for writes, exactly like the recon/sec
stores.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Sequence

from ..database import Database
from .migrate import migrate


class OpsStore:
    def __init__(self, database: Database) -> None:
        self._db = database

    @property
    def conn(self) -> sqlite3.Connection:
        return self._db.conn

    def ensure_schema(self, now: str) -> None:
        migrate(self._db, now)

    # -- runs ------------------------------------------------------------------------

    def start_run(self, program: str, started_at: str, pid: int, host: str) -> int:
        return int(self.conn.execute(
            "INSERT INTO ops_runs (program, started_at, status, pid, host) VALUES (?,?, 'running', ?, ?)",
            (program, started_at, pid, host)).lastrowid)

    def update_run_stages(self, run_id: int, stages: dict) -> None:
        self.conn.execute("UPDATE ops_runs SET stages_json=? WHERE id=?",
                          (json.dumps(stages), run_id))

    def finish_run(self, run_id: int, finished_at: str, status: str, summary: dict) -> None:
        self.conn.execute("UPDATE ops_runs SET finished_at=?, status=?, summary_json=? WHERE id=?",
                          (finished_at, status, json.dumps(summary), run_id))

    def latest_unfinished_run(self, program: str) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT * FROM ops_runs WHERE program=? AND status IN ('running','interrupted','failed') "
            "ORDER BY id DESC LIMIT 1", (program,)).fetchone()

    def last_completed_run_at(self, program: str) -> str | None:
        row = self.conn.execute(
            "SELECT finished_at FROM ops_runs WHERE program=? AND status='completed' "
            "ORDER BY id DESC LIMIT 1", (program,)).fetchone()
        return row[0] if row else None

    # -- fingerprints (incremental) --------------------------------------------------

    def fingerprint(self, object_type: str, object_key: str) -> str | None:
        row = self.conn.execute(
            "SELECT fingerprint FROM ops_fingerprints WHERE object_type=? AND object_key=?",
            (object_type, object_key)).fetchone()
        return row[0] if row else None

    def set_fingerprint(self, object_type: str, object_key: str, fingerprint: str, now: str) -> None:
        self.conn.execute(
            "INSERT INTO ops_fingerprints (object_type, object_key, fingerprint, updated_at) VALUES (?,?,?,?) "
            "ON CONFLICT(object_type,object_key) DO UPDATE SET fingerprint=excluded.fingerprint, updated_at=excluded.updated_at",
            (object_type, object_key, fingerprint, now))

    def changed(self, object_type: str, object_key: str, fingerprint: str) -> bool:
        return self.fingerprint(object_type, object_key) != fingerprint

    # -- feedback --------------------------------------------------------------------

    def add_feedback(self, program: str, kind: str, key: str, verdict: str, now: str) -> None:
        self.conn.execute(
            "INSERT INTO ops_feedback (program, target_kind, target_key, verdict, created_at) VALUES (?,?,?,?,?)",
            (program, kind, key, verdict, now))

    def feedback_counts(self, program: str, kind: str, key: str) -> dict[str, int]:
        rows = self.conn.execute(
            "SELECT verdict, COUNT(*) FROM ops_feedback WHERE program=? AND target_kind=? AND target_key=? GROUP BY verdict",
            (program, kind, key)).fetchall()
        return {r[0]: r[1] for r in rows}

    def category_feedback(self, program: str, category: str) -> dict[str, int]:
        return self.feedback_counts(program, "category", category)

    # -- ignore rules ----------------------------------------------------------------

    def add_ignore_rule(self, program: str, rule_type: str, pattern: str, note: str, now: str) -> int:
        return int(self.conn.execute(
            "INSERT INTO ops_ignore_rules (program, rule_type, pattern, note, created_at) VALUES (?,?,?,?,?)",
            (program, rule_type, pattern, note, now)).lastrowid)

    def ignore_rules(self, program: str) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM ops_ignore_rules WHERE program=? AND active=1 ORDER BY id", (program,)).fetchall()

    def deactivate_ignore_rule(self, rule_id: int) -> bool:
        return bool(self.conn.execute(
            "UPDATE ops_ignore_rules SET active=0 WHERE id=?", (rule_id,)).rowcount)

    # -- baselines -------------------------------------------------------------------

    def add_baseline(self, program: str, scope_kind: str, scope_key: str, expectation: str, note: str, now: str) -> None:
        self.conn.execute(
            "INSERT INTO ops_baselines (program, scope_kind, scope_key, expectation, note, created_at) "
            "VALUES (?,?,?,?,?,?) ON CONFLICT(program,scope_kind,scope_key,expectation) DO NOTHING",
            (program, scope_kind, scope_key, expectation, note, now))

    def baselines(self, program: str) -> list[sqlite3.Row]:
        return self.conn.execute("SELECT * FROM ops_baselines WHERE program=?", (program,)).fetchall()

    # -- finding lifecycle & lineage -------------------------------------------------

    def get_finding_state(self, dedup_key: str) -> sqlite3.Row | None:
        return self.conn.execute("SELECT * FROM ops_finding_state WHERE dedup_key=?", (dedup_key,)).fetchone()

    def upsert_finding_state(self, dedup_key: str, program: str, now: str,
                             lineage_key: str | None = None) -> sqlite3.Row:
        row = self.get_finding_state(dedup_key)
        if row is None:
            self.conn.execute(
                "INSERT INTO ops_finding_state (dedup_key, program, lifecycle, lineage_key, first_seen, last_seen) "
                "VALUES (?,?, 'new', ?, ?, ?)", (dedup_key, program, lineage_key or dedup_key, now, now))
        else:
            self.conn.execute("UPDATE ops_finding_state SET last_seen=? WHERE dedup_key=?", (now, dedup_key))
        return self.get_finding_state(dedup_key)

    def set_lifecycle(self, dedup_key: str, lifecycle: str, now: str) -> None:
        self.conn.execute("UPDATE ops_finding_state SET lifecycle=? WHERE dedup_key=?", (lifecycle, dedup_key))
        if lifecycle == "resolved":
            self.conn.execute("UPDATE ops_finding_state SET resolved_at=? WHERE dedup_key=?", (now, dedup_key))

    def bump_regressed(self, dedup_key: str, now: str) -> None:
        self.conn.execute(
            "UPDATE ops_finding_state SET regressed_count=regressed_count+1, resolved_at=NULL, "
            "lifecycle='investigating' WHERE dedup_key=?", (dedup_key,))

    def add_timeline(self, dedup_key: str, event: str, detail: str | None, now: str) -> None:
        self.conn.execute(
            "INSERT INTO ops_finding_timeline (dedup_key, event, detail, created_at) VALUES (?,?,?,?)",
            (dedup_key, event, detail, now))

    def timeline(self, dedup_key: str) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT event, detail, created_at FROM ops_finding_timeline WHERE dedup_key=? ORDER BY id",
            (dedup_key,)).fetchall()

    # -- notes -----------------------------------------------------------------------

    def add_note(self, program: str, kind: str, key: str, note: str, now: str) -> None:
        self.conn.execute(
            "INSERT INTO ops_notes (program, target_kind, target_key, note, created_at) VALUES (?,?,?,?,?)",
            (program, kind, key, note, now))

    def notes(self, program: str, kind: str, key: str) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT note, created_at FROM ops_notes WHERE program=? AND target_kind=? AND target_key=? ORDER BY id",
            (program, kind, key)).fetchall()

    # -- notifications (dedup) -------------------------------------------------------

    def notification_seen(self, program: str, dedup_key: str) -> bool:
        return self.conn.execute(
            "SELECT 1 FROM ops_notifications WHERE program=? AND dedup_key=?", (program, dedup_key)).fetchone() is not None

    def record_notification(self, program: str, event_type: str, dedup_key: str, priority: int, now: str) -> bool:
        cur = self.conn.execute(
            "INSERT INTO ops_notifications (program, event_type, dedup_key, priority, sent_at) VALUES (?,?,?,?,?) "
            "ON CONFLICT(program,dedup_key) DO NOTHING", (program, event_type, dedup_key, priority, now))
        return bool(cur.rowcount)

    # -- tool health -----------------------------------------------------------------

    def record_tool_health(self, tool: str, version: str | None, available: bool,
                           now: str, success: bool = False, error: str | None = None,
                           timeout: bool = False, parse_failure: bool = False) -> None:
        self.conn.execute(
            """INSERT INTO ops_tool_health (tool, version, available, last_success, last_error, timeouts, parse_failures, updated_at)
               VALUES (?,?,?,?,?,?,?,?)
               ON CONFLICT(tool) DO UPDATE SET version=excluded.version, available=excluded.available,
                 last_success=CASE WHEN ? THEN excluded.updated_at ELSE ops_tool_health.last_success END,
                 last_error=COALESCE(excluded.last_error, ops_tool_health.last_error),
                 timeouts=ops_tool_health.timeouts + ?, parse_failures=ops_tool_health.parse_failures + ?,
                 updated_at=excluded.updated_at""",
            (tool, version, int(available), now if success else None, error,
             int(timeout), int(parse_failure), now, int(success), int(timeout), int(parse_failure)))

    def tool_health(self) -> list[sqlite3.Row]:
        return self.conn.execute("SELECT * FROM ops_tool_health ORDER BY tool").fetchall()

    # -- metrics ---------------------------------------------------------------------

    def add_metric(self, run_id: int | None, stage: str | None, metric: str, value: float, now: str) -> None:
        self.conn.execute(
            "INSERT INTO ops_metrics (run_id, stage, metric, value, created_at) VALUES (?,?,?,?,?)",
            (run_id, stage, metric, value, now))

    def run_metrics(self, run_id: int) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT stage, metric, value FROM ops_metrics WHERE run_id=? ORDER BY id", (run_id,)).fetchall()

    # -- ai feedback -----------------------------------------------------------------

    def add_ai_feedback(self, program: str, fingerprint: str, provider: str | None, verdict: str, now: str) -> None:
        self.conn.execute(
            "INSERT INTO ops_ai_feedback (program, evidence_fingerprint, provider, verdict, created_at) VALUES (?,?,?,?,?)",
            (program, fingerprint, provider, verdict, now))

    def ai_feedback_stats(self, program: str) -> dict[str, int]:
        rows = self.conn.execute(
            "SELECT verdict, COUNT(*) FROM ops_ai_feedback WHERE program=? GROUP BY verdict", (program,)).fetchall()
        return {r[0]: r[1] for r in rows}
