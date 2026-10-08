"""Researcher review queue: formatting and status transitions (CLI-facing)."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Sequence

from ..database import Database
from ..utils import utc_now_iso
from .recon_db import ReconStore

VALID_STATUSES = ("new", "reviewing", "interesting", "dismissed", "resolved")


def format_queue(rows: Sequence[sqlite3.Row], *, detail: bool = True) -> str:
    """Render review items as the researcher-facing queue.

    Each item shows priority, asset and status, then its underlying signals.
    """
    if not rows:
        return "Review queue is empty."
    lines: list[str] = ["Researcher review queue", ""]
    for row in rows:
        signals = _signals(row)
        status = row["status"]
        tag = "" if status == "new" else f"  ({status})"
        lines.append(f"[{row['review_priority']:>3}] {row['asset']}{tag}")
        if detail:
            for signal in signals:
                lines.append(f"      - {signal}")
            lines.append(f"      first_seen={row['first_seen']}  latest_seen={row['latest_seen']}")
    return "\n".join(lines)


def _signals(row: sqlite3.Row) -> list[str]:
    try:
        parsed = json.loads(row["signals_json"])
        return parsed if isinstance(parsed, list) else [row["reason"]]
    except (ValueError, TypeError, IndexError):
        return [row["reason"]]


def show_queue(database: str, *, statuses: Sequence[str] | None = None, limit: int = 100, detail: bool = True) -> str:
    db = Database(database)
    db.open()
    try:
        store = ReconStore(db)
        store.ensure_schema()
        rows = store.review_queue(statuses, limit)
        return format_queue(rows, detail=detail)
    finally:
        db.close()


def set_status(database: str, asset: str, status: str) -> bool:
    if status not in VALID_STATUSES:
        raise ValueError(f"invalid status {status!r}; choose from {', '.join(VALID_STATUSES)}")
    db = Database(database)
    db.open()
    try:
        store = ReconStore(db)
        store.ensure_schema()
        with db.transaction():
            return store.set_review_status(asset, status, utc_now_iso())
    finally:
        db.close()
