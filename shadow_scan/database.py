"""SQLite persistence layer.

Concurrency model: exactly one ``Database`` connection exists per run, and the
scanner only ever touches it from a single dedicated worker thread. SQLite
therefore never sees concurrent writers from inside ShadowScan. WAL mode lets
external readers (dashboards, ad-hoc queries) read while a scan writes.

Per-observation cost is constant. Each asset row keeps pointers to its latest
and latest-complete observations, plus running history counters. Change
detection therefore never scans an asset's history: it does primary-key
lookups only.

Schema versioning: ``PRAGMA user_version``. A new database is created at
:data:`SCHEMA_VERSION`. Schema v2 changed asset identity from "probe URL" to
"host[:port][/path]". Phase 1 (v1) databases are refused with instructions
instead of being migrated, because merging assets under the new identity
would require rewriting history.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import Self

from .models import AssetHistory, Change, PreviousObservation, ProbeResult, RunStatus, Target

logger = logging.getLogger(__name__)

SCHEMA_VERSION = 2

_SCHEMA = """
BEGIN;

CREATE TABLE IF NOT EXISTS runs (
    id                  INTEGER PRIMARY KEY,
    started_at          TEXT    NOT NULL,
    finished_at         TEXT,
    status              TEXT    NOT NULL,
    targets_total       INTEGER NOT NULL DEFAULT 0,
    targets_processed   INTEGER NOT NULL DEFAULT 0,
    reachable           INTEGER NOT NULL DEFAULT 0,
    unreachable         INTEGER NOT NULL DEFAULT 0,
    incomplete          INTEGER NOT NULL DEFAULT 0,
    changes_found       INTEGER NOT NULL DEFAULT 0,
    interesting_changes INTEGER NOT NULL DEFAULT 0,
    raw_only_changes    INTEGER NOT NULL DEFAULT 0
);

-- One row per monitored asset. Identity is host[:port][/path] WITHOUT the scheme,
-- so "example.com" and "https://example.com" are the same asset.
CREATE TABLE IF NOT EXISTS assets (
    id                           INTEGER PRIMARY KEY,
    target                       TEXT    NOT NULL UNIQUE,   -- identity key
    hostname                     TEXT    NOT NULL,
    port                         INTEGER,                   -- only when explicitly supplied (non-default)
    path                         TEXT    NOT NULL DEFAULT '',
    requested_scheme             TEXT,                      -- 'http'/'https' if explicit; NULL = auto (HTTPS then HTTP)
    original_input               TEXT    NOT NULL,          -- latest input line for this asset
    first_seen                   TEXT    NOT NULL,
    last_seen                    TEXT    NOT NULL,
    last_observation_id          INTEGER REFERENCES observations(id) ON DELETE SET NULL,
    last_complete_observation_id INTEGER REFERENCES observations(id) ON DELETE SET NULL,
    -- Historical noise metrics, maintained incrementally.
    observations_count           INTEGER NOT NULL DEFAULT 0,
    content_comparisons          INTEGER NOT NULL DEFAULT 0,
    content_change_count         INTEGER NOT NULL DEFAULT 0,
    last_content_change_at       TEXT
);
CREATE INDEX IF NOT EXISTS idx_assets_hostname ON assets(hostname);

CREATE TABLE IF NOT EXISTS observations (
    id                    INTEGER PRIMARY KEY,
    asset_id              INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    run_id                INTEGER REFERENCES runs(id) ON DELETE SET NULL,
    checked_at            TEXT    NOT NULL,
    url                   TEXT    NOT NULL,                 -- first URL requested
    final_url             TEXT,
    scheme                TEXT,                             -- scheme that actually answered
    hostname              TEXT,
    fallback_used         INTEGER NOT NULL DEFAULT 0,
    http_reachable        INTEGER NOT NULL DEFAULT 0,
    observation_complete  INTEGER NOT NULL DEFAULT 0,
    status_code           INTEGER,
    content_type          TEXT,
    content_length_header INTEGER,
    downloaded_bytes      INTEGER NOT NULL DEFAULT 0,
    body_truncated        INTEGER NOT NULL DEFAULT 0,
    body_sha256           TEXT,                             -- raw SHA-256
    normalized_sha256     TEXT,
    content_similarity    REAL,                             -- vs content_baseline_observation_id
    content_baseline_observation_id INTEGER REFERENCES observations(id) ON DELETE SET NULL,
    title                 TEXT,
    server_header         TEXT,
    redirect_location     TEXT,
    redirect_count        INTEGER NOT NULL DEFAULT 0,
    response_time_ms      REAL,
    error_type            TEXT,
    error_message         TEXT
);
CREATE INDEX IF NOT EXISTS idx_observations_asset_latest ON observations(asset_id, id DESC);
CREATE INDEX IF NOT EXISTS idx_observations_run ON observations(run_id);
CREATE INDEX IF NOT EXISTS idx_observations_checked_at ON observations(checked_at);
CREATE INDEX IF NOT EXISTS idx_observations_body_sha256 ON observations(body_sha256);
CREATE INDEX IF NOT EXISTS idx_observations_normalized_sha256 ON observations(normalized_sha256);

-- Extensible key/value store for fingerprint strategies (see fingerprint.py).
CREATE TABLE IF NOT EXISTS observation_fingerprints (
    observation_id INTEGER NOT NULL REFERENCES observations(id) ON DELETE CASCADE,
    name           TEXT    NOT NULL,
    value          TEXT    NOT NULL,
    PRIMARY KEY (observation_id, name)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS idx_fingerprints_name_value ON observation_fingerprints(name, value);

-- Similarity sketch of each asset's content baseline (latest complete textual observation).
-- Exactly one row per asset, overwritten in place, so storage stays bounded.
CREATE TABLE IF NOT EXISTS asset_content_baselines (
    asset_id       INTEGER PRIMARY KEY REFERENCES assets(id) ON DELETE CASCADE,
    observation_id INTEGER NOT NULL REFERENCES observations(id) ON DELETE CASCADE,
    sketch         BLOB    NOT NULL
);

CREATE TABLE IF NOT EXISTS changes (
    id                      INTEGER PRIMARY KEY,
    run_id                  INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    asset_id                INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    observation_id          INTEGER NOT NULL REFERENCES observations(id) ON DELETE CASCADE,
    previous_observation_id INTEGER REFERENCES observations(id) ON DELETE SET NULL,
    change_type             TEXT    NOT NULL,
    interesting             INTEGER NOT NULL DEFAULT 0,
    review_priority         INTEGER NOT NULL DEFAULT 0,
    reason                  TEXT,
    detected_at             TEXT    NOT NULL,
    details                 TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_changes_run_priority ON changes(run_id, review_priority DESC);
CREATE INDEX IF NOT EXISTS idx_changes_asset ON changes(asset_id, id);
CREATE INDEX IF NOT EXISTS idx_changes_type ON changes(change_type);
CREATE INDEX IF NOT EXISTS idx_changes_interesting ON changes(interesting, id) WHERE interesting = 1;

COMMIT;
"""

_OBSERVATION_COLUMNS = (
    "id, checked_at, status_code, body_sha256, normalized_sha256, title, redirect_location, "
    "final_url, error_type, server_header, observation_complete"
)


@dataclass(frozen=True, slots=True)
class AssetState:
    """An asset row as needed by the writer: identity, pointers and history."""

    id: int
    created: bool
    last_observation_id: int | None
    last_complete_observation_id: int | None
    history: AssetHistory


class Database:
    """Thin, explicit wrapper around one SQLite connection.

    Not thread-safe by design: callers must use it from one thread at a time.
    """

    def __init__(self, path: Path | str) -> None:
        self._path = str(path)
        self._conn: sqlite3.Connection | None = None

    # -- lifecycle ---------------------------------------------------------------

    def open(self) -> None:
        if self._conn is not None:
            return
        if self._path != ":memory:":
            Path(self._path).parent.mkdir(parents=True, exist_ok=True)
        # isolation_level=None: we issue BEGIN/COMMIT ourselves, so batching is explicit.
        conn = sqlite3.connect(self._path, isolation_level=None, timeout=30.0)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA foreign_keys = ON")
            mode = conn.execute("PRAGMA journal_mode = WAL").fetchone()[0]
            if str(mode).lower() != "wal":
                logger.warning("SQLite WAL mode unavailable for %s (journal_mode=%s)", self._path, mode)
            conn.execute("PRAGMA synchronous = NORMAL")  # safe with WAL; far fewer fsyncs
            conn.execute("PRAGMA busy_timeout = 30000")
            self._conn = conn
            self._initialize_schema()
        except BaseException:
            conn.close()
            self._conn = None
            raise

    def close(self) -> None:
        if self._conn is None:
            return
        try:
            self._conn.execute("PRAGMA optimize")
        except sqlite3.Error:
            pass
        finally:
            self._conn.close()
            self._conn = None

    def __enter__(self) -> Self:
        self.open()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    @property
    def conn(self) -> sqlite3.Connection:
        if self._conn is None:
            raise RuntimeError("database is not open")
        return self._conn

    def _initialize_schema(self) -> None:
        version = self.conn.execute("PRAGMA user_version").fetchone()[0]
        if version > SCHEMA_VERSION:
            raise RuntimeError(
                f"database schema version {version} is newer than supported version {SCHEMA_VERSION}"
            )
        if 0 < version < SCHEMA_VERSION:
            raise RuntimeError(
                f"{self._path} uses ShadowScan schema v{version}; this version needs v{SCHEMA_VERSION} "
                "(asset identity changed to host-based). Keep the old file for reference and pass a new "
                "--database path, or move the old file aside."
            )
        self.conn.executescript(_SCHEMA)
        if version < SCHEMA_VERSION:
            self.conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """One write transaction. BEGIN IMMEDIATE takes the write lock up front,
        so a concurrent external writer surfaces as busy_timeout waiting instead
        of a mid-transaction failure."""
        conn = self.conn
        conn.execute("BEGIN IMMEDIATE")
        try:
            yield conn
        except BaseException:
            conn.execute("ROLLBACK")
            raise
        else:
            conn.execute("COMMIT")

    # -- runs ----------------------------------------------------------------------

    def start_run(self, started_at: str, targets_total: int) -> int:
        with self.transaction() as conn:
            cursor = conn.execute(
                "INSERT INTO runs (started_at, status, targets_total) VALUES (?, ?, ?)",
                (started_at, RunStatus.RUNNING.value, targets_total),
            )
            return int(cursor.lastrowid)

    def finish_run(
        self,
        run_id: int,
        finished_at: str,
        status: RunStatus,
        targets_processed: int,
        reachable: int,
        unreachable: int,
        changes_found: int,
        incomplete: int = 0,
        interesting_changes: int = 0,
        raw_only_changes: int = 0,
    ) -> None:
        with self.transaction() as conn:
            conn.execute(
                """UPDATE runs SET finished_at = ?, status = ?, targets_processed = ?, reachable = ?,
                       unreachable = ?, incomplete = ?, changes_found = ?, interesting_changes = ?,
                       raw_only_changes = ?
                   WHERE id = ?""",
                (finished_at, status.value, targets_processed, reachable, unreachable, incomplete,
                 changes_found, interesting_changes, raw_only_changes, run_id),
            )

    # -- per-observation operations (call inside transaction()) ------------------------

    def upsert_asset(self, target: Target, seen_at: str) -> AssetState:
        """Create or refresh the asset row and return its current state.

        The requested scheme and original input are refreshed from the latest
        input, so editing ``domains.txt`` from ``example.com`` to
        ``https://example.com`` changes intent without creating a new asset.
        """
        row = self.conn.execute(
            """SELECT id, last_observation_id, last_complete_observation_id,
                      observations_count, content_comparisons, content_change_count
               FROM assets WHERE target = ?""",
            (target.key,),
        ).fetchone()
        if row is not None:
            self.conn.execute(
                """UPDATE assets SET last_seen = ?, requested_scheme = ?, original_input = ?
                   WHERE id = ?""",
                (seen_at, target.scheme, target.original or target.key, row["id"]),
            )
            return AssetState(
                id=row["id"],
                created=False,
                last_observation_id=row["last_observation_id"],
                last_complete_observation_id=row["last_complete_observation_id"],
                history=AssetHistory(row["observations_count"], row["content_comparisons"], row["content_change_count"]),
            )
        cursor = self.conn.execute(
            """INSERT INTO assets (target, hostname, port, path, requested_scheme, original_input, first_seen, last_seen)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (target.key, target.hostname, target.port, target.path, target.scheme,
             target.original or target.key, seen_at, seen_at),
        )
        return AssetState(int(cursor.lastrowid), True, None, None, AssetHistory())

    def get_observation(self, observation_id: int | None) -> PreviousObservation | None:
        if observation_id is None:
            return None
        row = self.conn.execute(
            f"SELECT {_OBSERVATION_COLUMNS} FROM observations WHERE id = ?", (observation_id,)
        ).fetchone()
        return None if row is None else self._to_previous(row)

    def latest_observation(self, asset_id: int) -> PreviousObservation | None:
        """Most recent observation for an asset (index seek; used by tooling/tests)."""
        row = self.conn.execute(
            f"SELECT {_OBSERVATION_COLUMNS} FROM observations WHERE asset_id = ? ORDER BY id DESC LIMIT 1",
            (asset_id,),
        ).fetchone()
        return None if row is None else self._to_previous(row)

    @staticmethod
    def _to_previous(row: sqlite3.Row) -> PreviousObservation:
        return PreviousObservation(
            id=row["id"],
            checked_at=row["checked_at"],
            status_code=row["status_code"],
            body_sha256=row["body_sha256"],
            title=row["title"],
            redirect_location=row["redirect_location"],
            final_url=row["final_url"],
            error_type=row["error_type"],
            normalized_sha256=row["normalized_sha256"],
            server_header=row["server_header"],
            observation_complete=bool(row["observation_complete"]),
        )

    def get_baseline_sketch(self, asset_id: int, observation_id: int) -> bytes | None:
        """The stored sketch, only if it belongs to the given baseline observation."""
        row = self.conn.execute(
            "SELECT sketch FROM asset_content_baselines WHERE asset_id = ? AND observation_id = ?",
            (asset_id, observation_id),
        ).fetchone()
        return None if row is None else bytes(row["sketch"])

    def set_baseline_sketch(
        self, asset_id: int, observation_id: int, sketch: bytes | None, content_unchanged: bool = False
    ) -> None:
        """Make ``observation_id`` the asset's content baseline.

        ``None`` removes the sketch, so a stale sketch can never be compared
        against a newer baseline. When the content is unchanged the sketch is
        identical by construction, so only the pointer moves and the blob is
        not rewritten on every run.
        """
        if content_unchanged:
            self.conn.execute(
                "UPDATE asset_content_baselines SET observation_id = ? WHERE asset_id = ?",
                (observation_id, asset_id),
            )
            return
        if sketch is None:
            self.conn.execute("DELETE FROM asset_content_baselines WHERE asset_id = ?", (asset_id,))
            return
        self.conn.execute(
            """INSERT INTO asset_content_baselines (asset_id, observation_id, sketch) VALUES (?, ?, ?)
               ON CONFLICT(asset_id) DO UPDATE SET observation_id = excluded.observation_id, sketch = excluded.sketch""",
            (asset_id, observation_id, sketch),
        )

    def insert_observation(
        self,
        asset_id: int,
        run_id: int | None,
        result: ProbeResult,
        content_similarity: float | None = None,
        content_baseline_observation_id: int | None = None,
    ) -> int:
        cursor = self.conn.execute(
            """INSERT INTO observations (
                   asset_id, run_id, checked_at, url, final_url, scheme, hostname, fallback_used,
                   http_reachable, observation_complete, status_code, content_type, content_length_header,
                   downloaded_bytes, body_truncated, body_sha256, normalized_sha256, content_similarity,
                   content_baseline_observation_id, title, server_header, redirect_location, redirect_count,
                   response_time_ms, error_type, error_message)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                asset_id,
                run_id,
                result.checked_at,
                result.url,
                result.final_url,
                result.scheme,
                result.hostname,
                int(result.fallback_used),
                int(result.http_reachable),
                int(result.observation_complete),
                result.status_code,
                result.content_type,
                result.content_length_header,
                result.downloaded_bytes,
                int(result.body_truncated),
                result.body_sha256,
                result.normalized_sha256,
                content_similarity,
                content_baseline_observation_id,
                result.title,
                result.server_header,
                result.redirect_location,
                result.redirect_count,
                result.response_time_ms,
                result.error_type.value if result.error_type else None,
                result.error_message,
            ),
        )
        return int(cursor.lastrowid)

    def update_asset_after_observation(
        self,
        asset_id: int,
        observation_id: int,
        complete: bool,
        history: AssetHistory,
        content_changed_at: str | None,
    ) -> None:
        self.conn.execute(
            """UPDATE assets SET
                   last_observation_id = ?,
                   last_complete_observation_id = CASE WHEN ? THEN ? ELSE last_complete_observation_id END,
                   observations_count = ?, content_comparisons = ?, content_change_count = ?,
                   last_content_change_at = COALESCE(?, last_content_change_at)
               WHERE id = ?""",
            (observation_id, int(complete), observation_id, history.observations,
             history.content_comparisons, history.content_changes, content_changed_at, asset_id),
        )

    def insert_fingerprints(self, observation_id: int, fingerprints: Mapping[str, str]) -> None:
        if fingerprints:
            self.conn.executemany(
                "INSERT INTO observation_fingerprints (observation_id, name, value) VALUES (?, ?, ?)",
                [(observation_id, name, value) for name, value in fingerprints.items()],
            )

    def insert_change(
        self,
        run_id: int,
        asset_id: int,
        observation_id: int,
        previous_observation_id: int | None,
        change: Change,
        detected_at: str,
    ) -> None:
        self.conn.execute(
            """INSERT INTO changes (run_id, asset_id, observation_id, previous_observation_id,
                                    change_type, interesting, review_priority, reason, detected_at, details)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                run_id,
                asset_id,
                observation_id,
                previous_observation_id,
                change.change_type.value,
                int(change.interesting),
                change.review_priority,
                change.reason,
                detected_at,
                json.dumps(change.to_dict(), ensure_ascii=False, sort_keys=True),
            ),
        )
