"""Structured logging: human console or JSON, with bounded rotating file output.

Never logs secrets (ShadowScan redacts before anything reaches a log record).
JSON records carry stable fields for ingestion.
"""

from __future__ import annotations

import json
import logging
import logging.handlers
import sys
from pathlib import Path

_FIELDS = ("program", "run_id", "stage", "host", "event", "priority", "error_type")


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for field in _FIELDS:
            if hasattr(record, field):
                payload[field] = getattr(record, field)
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)[:2000]
        return json.dumps(payload, ensure_ascii=False)


def configure(*, json_output: bool = False, verbose: bool = False,
              log_file: Path | str | None = None, max_bytes: int = 5 * 1024 * 1024,
              backups: int = 3) -> None:
    """Configure root logging. Console is human-readable unless ``json_output``."""
    root = logging.getLogger()
    root.handlers[:] = []
    root.setLevel(logging.DEBUG if verbose else logging.INFO)

    console = logging.StreamHandler(sys.stderr)
    console.setFormatter(JsonFormatter() if json_output
                         else logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S"))
    root.addHandler(console)

    if log_file is not None:
        path = Path(log_file)
        path.parent.mkdir(parents=True, exist_ok=True)
        rotating = logging.handlers.RotatingFileHandler(
            path, maxBytes=max_bytes, backupCount=backups, encoding="utf-8")
        rotating.setFormatter(JsonFormatter())   # file is always JSON for ingestion
        root.addHandler(rotating)

    for noisy in ("aiohttp", "asyncio"):
        logging.getLogger(noisy).setLevel(logging.DEBUG if verbose else logging.WARNING)
