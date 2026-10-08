"""Database maintenance, backup, and versioned export/import.

Backups use SQLite's online backup API (never a naive file copy of a live DB).
Export/import use a versioned JSON envelope and never include authentication
secrets. Core historical findings are never deleted by default; retention only
trims bulky transient rows when explicitly requested.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..database import Database

EXPORT_VERSION = 1
# Tables exported as program intelligence (secrets are never here by construction).
_EXPORT_TABLES = (
    "assets", "endpoints", "parameters", "urls", "dns_records", "services",
    "javascript_assets", "js_findings", "technologies", "review_items",
    "security_findings", "finding_evidence", "ops_finding_state", "ops_finding_timeline",
    "ops_notes", "ops_feedback", "ops_ignore_rules", "ops_baselines",
)
# Bulky transient tables eligible for retention trimming.
_TRANSIENT_TABLES = ("observations", "ops_metrics", "asset_content_baselines")


@dataclass(frozen=True, slots=True)
class DbStats:
    page_count: int
    page_size: int
    size_bytes: int
    tables: dict[str, int]


def stats(database: Database) -> DbStats:
    conn = database.conn
    pc = conn.execute("PRAGMA page_count").fetchone()[0]
    ps = conn.execute("PRAGMA page_size").fetchone()[0]
    tables = {}
    for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"):
        name = row[0]
        try:
            tables[name] = conn.execute(f"SELECT COUNT(*) FROM {name}").fetchone()[0]
        except sqlite3.Error:
            tables[name] = -1
    return DbStats(pc, ps, pc * ps, tables)


def integrity_check(database: Database) -> tuple[bool, str]:
    result = database.conn.execute("PRAGMA integrity_check").fetchone()[0]
    fk = database.conn.execute("PRAGMA foreign_key_check").fetchall()
    ok = result == "ok" and not fk
    detail = result if result != "ok" else (f"foreign key violations: {len(fk)}" if fk else "ok")
    return ok, detail


def vacuum(database: Database) -> None:
    database.conn.execute("VACUUM")


def backup(database: Database, dest: Path | str) -> Path:
    """Consistent online backup via the SQLite backup API."""
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    target = sqlite3.connect(str(dest))
    try:
        database.conn.backup(target)   # online backup API: consistent, not a naive file copy
    finally:
        target.close()                 # must close, or Windows keeps the file locked
    return dest


def export_program(database: Database, program: str, dest: Path | str) -> Path:
    """Export program intelligence to a versioned JSON envelope (no secrets)."""
    conn = database.conn
    payload: dict[str, Any] = {"export_version": EXPORT_VERSION, "program": program, "tables": {}}
    for table in _EXPORT_TABLES:
        if not _table_exists(conn, table):
            continue
        cols = [r[1] for r in conn.execute(f"PRAGMA table_info({table})")]
        # Defense-in-depth: never export any column that could carry a secret.
        safe_cols = [c for c in cols if not _is_secretish(c)]
        rows = [dict(zip(safe_cols, r)) for r in
                conn.execute(f"SELECT {', '.join(safe_cols)} FROM {table}")]
        payload["tables"][table] = {"columns": safe_cols, "rows": rows}
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return dest


@dataclass(frozen=True, slots=True)
class ImportValidation:
    ok: bool
    version: int
    program: str
    table_counts: dict[str, int]
    errors: list[str]


def validate_export(path: Path | str) -> ImportValidation:
    """Validate an export envelope before importing (does not mutate anything)."""
    errors: list[str] = []
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return ImportValidation(False, 0, "", {}, [f"unreadable: {exc}"])
    version = int(payload.get("export_version", 0))
    if version != EXPORT_VERSION:
        errors.append(f"unsupported export_version {version} (expected {EXPORT_VERSION})")
    if not isinstance(payload.get("tables"), dict):
        errors.append("missing 'tables'")
    counts = {t: len(v.get("rows", [])) for t, v in (payload.get("tables", {}) or {}).items()
              if isinstance(v, dict)}
    for table, block in (payload.get("tables", {}) or {}).items():
        for col in (block.get("columns", []) if isinstance(block, dict) else []):
            if _is_secretish(col):
                errors.append(f"export contains a secret-like column {table}.{col}")
    return ImportValidation(not errors, version, str(payload.get("program", "")), counts, errors)


def retention_trim(database: Database, *, keep_latest_observations: int = 0) -> dict[str, int]:
    """Trim bulky transient rows (never core findings). Returns rows removed per table.

    With ``keep_latest_observations`` > 0, keep only the N most recent observations
    per asset. ops_metrics older rows can be cleared entirely. Core findings and
    history are untouched.
    """
    conn = database.conn
    removed: dict[str, int] = {}
    if keep_latest_observations > 0 and _table_exists(conn, "observations"):
        cur = conn.execute(
            """DELETE FROM observations WHERE id IN (
                 SELECT id FROM (
                   SELECT id, ROW_NUMBER() OVER (PARTITION BY asset_id ORDER BY id DESC) AS rn
                   FROM observations) WHERE rn > ?)""", (keep_latest_observations,))
        removed["observations"] = cur.rowcount
    return removed


def _table_exists(conn: sqlite3.Connection, name: str) -> bool:
    return conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone() is not None


def _is_secretish(column: str) -> bool:
    c = column.lower()
    return any(tok in c for tok in ("token", "secret", "password", "cookie", "authorization", "credential"))
