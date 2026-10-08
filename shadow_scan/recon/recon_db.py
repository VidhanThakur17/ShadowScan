"""Recon persistence, layered on the existing monitoring :class:`Database`.

This reuses the monitoring connection, WAL and single-writer model rather than
opening a second datastore. Recon tables are created additively with
``CREATE TABLE IF NOT EXISTS`` and tracked by ``recon_meta`` (so the monitoring
``PRAGMA user_version`` is untouched and a monitoring-only DB keeps working).

All methods here must run on the one DB thread, inside a surrounding
``database.transaction()`` where a transaction is noted, exactly like the
monitoring writer. Upsert helpers return whether the row was new (and any
transitions), so the pipeline stays thin and does not re-query history.

Identity is by normalized string (hostname, URL, endpoint identity) with unique
indexes, so the same object discovered by several sources does not duplicate.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable, Sequence

from ..database import Database
from . import RECON_SCHEMA_VERSION
from .dns import dns_transitions
from .models import (
    DnsRecord,
    Endpoint,
    JsFinding,
    Parameter,
    ReconEvent,
    ReconSignal,
    ScopeClass,
    Service,
    StageStatus,
    Technology,
    UrlRecord,
)

_RECON_SCHEMA = """
CREATE TABLE IF NOT EXISTS recon_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS recon_runs (
    id          INTEGER PRIMARY KEY,
    started_at  TEXT NOT NULL,
    finished_at TEXT,
    status      TEXT NOT NULL,
    scope_hash  TEXT
);

CREATE TABLE IF NOT EXISTS recon_stages (
    run_id      INTEGER NOT NULL REFERENCES recon_runs(id) ON DELETE CASCADE,
    stage       TEXT NOT NULL,
    status      TEXT NOT NULL,
    started_at  TEXT,
    finished_at TEXT,
    detail      TEXT,
    PRIMARY KEY (run_id, stage)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS hosts (
    id          INTEGER PRIMARY KEY,
    hostname    TEXT NOT NULL UNIQUE,
    scope_class TEXT NOT NULL,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS discovery_sources (
    host_id    INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    source     TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    PRIMARY KEY (host_id, source)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS dns_records (
    host_id     INTEGER PRIMARY KEY REFERENCES hosts(id) ON DELETE CASCADE,
    status      TEXT NOT NULL,
    a_json      TEXT NOT NULL DEFAULT '[]',
    aaaa_json   TEXT NOT NULL DEFAULT '[]',
    cname       TEXT,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    changed_at  TEXT
);

CREATE TABLE IF NOT EXISTS services (
    id            INTEGER PRIMARY KEY,
    host          TEXT NOT NULL,
    port          INTEGER NOT NULL,
    protocol      TEXT NOT NULL DEFAULT 'tcp',
    service_guess TEXT,
    banner        TEXT,
    source        TEXT,
    status        TEXT NOT NULL DEFAULT 'open',
    first_seen    TEXT NOT NULL,
    last_seen     TEXT NOT NULL,
    UNIQUE (host, port, protocol)
);
CREATE INDEX IF NOT EXISTS idx_services_host ON services(host);

CREATE TABLE IF NOT EXISTS urls (
    id          INTEGER PRIMARY KEY,
    url         TEXT NOT NULL UNIQUE,
    host        TEXT NOT NULL,
    path        TEXT NOT NULL,
    param_names TEXT NOT NULL DEFAULT '',
    source      TEXT,
    status_code INTEGER,
    scope_class TEXT NOT NULL,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_urls_host ON urls(host);

CREATE TABLE IF NOT EXISTS javascript_assets (
    id                INTEGER PRIMARY KEY,
    url               TEXT NOT NULL UNIQUE,
    host              TEXT NOT NULL,
    raw_sha256        TEXT,
    normalized_sha256 TEXT,
    size              INTEGER,
    source_map        TEXT,
    first_seen        TEXT NOT NULL,
    last_seen         TEXT NOT NULL,
    changed_at        TEXT
);
CREATE INDEX IF NOT EXISTS idx_js_host ON javascript_assets(host);

CREATE TABLE IF NOT EXISTS js_findings (
    id            INTEGER PRIMARY KEY,
    js_id         INTEGER NOT NULL REFERENCES javascript_assets(id) ON DELETE CASCADE,
    finding_type  TEXT NOT NULL,
    value         TEXT NOT NULL,
    confidence    REAL NOT NULL DEFAULT 0.5,
    evidence      TEXT,
    first_seen    TEXT NOT NULL,
    UNIQUE (js_id, finding_type, value)
);
CREATE INDEX IF NOT EXISTS idx_js_findings_type ON js_findings(finding_type);

CREATE TABLE IF NOT EXISTS endpoints (
    id               INTEGER PRIMARY KEY,
    identity         TEXT NOT NULL UNIQUE,
    host             TEXT NOT NULL,
    path             TEXT NOT NULL,
    method           TEXT NOT NULL,
    method_confidence TEXT NOT NULL,
    param_names      TEXT NOT NULL DEFAULT '',
    source           TEXT,
    confidence       REAL NOT NULL DEFAULT 0.5,
    first_seen       TEXT NOT NULL,
    last_seen        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_endpoints_host ON endpoints(host);

CREATE TABLE IF NOT EXISTS parameters (
    id                INTEGER PRIMARY KEY,
    name              TEXT NOT NULL,
    location          TEXT NOT NULL,
    endpoint_identity TEXT,
    source            TEXT,
    confidence        REAL NOT NULL DEFAULT 0.5,
    first_seen        TEXT NOT NULL,
    last_seen         TEXT NOT NULL,
    UNIQUE (name, location, endpoint_identity)
);
CREATE INDEX IF NOT EXISTS idx_parameters_name ON parameters(name);

CREATE TABLE IF NOT EXISTS technologies (
    id         INTEGER PRIMARY KEY,
    host       TEXT NOT NULL,
    name       TEXT NOT NULL,
    version    TEXT,
    confidence REAL NOT NULL DEFAULT 0.5,
    evidence   TEXT,
    first_seen TEXT NOT NULL,
    last_seen  TEXT NOT NULL,
    removed_at TEXT,
    UNIQUE (host, name)
);
CREATE INDEX IF NOT EXISTS idx_tech_host ON technologies(host);

CREATE TABLE IF NOT EXISTS favicons (
    id         INTEGER PRIMARY KEY,
    host       TEXT NOT NULL,
    sha256     TEXT NOT NULL,
    is_current INTEGER NOT NULL DEFAULT 1,
    first_seen TEXT NOT NULL,
    last_seen  TEXT NOT NULL,
    UNIQUE (host, sha256)
);

CREATE TABLE IF NOT EXISTS recon_signals (
    id              INTEGER PRIMARY KEY,
    run_id          INTEGER REFERENCES recon_runs(id) ON DELETE SET NULL,
    rule_id         TEXT NOT NULL,
    asset           TEXT NOT NULL,
    reason          TEXT NOT NULL,
    review_priority INTEGER NOT NULL,
    evidence        TEXT NOT NULL DEFAULT '{}',
    detected_at     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_recon_signals_run ON recon_signals(run_id, review_priority DESC);
CREATE INDEX IF NOT EXISTS idx_recon_signals_asset ON recon_signals(asset);

CREATE TABLE IF NOT EXISTS review_items (
    id              INTEGER PRIMARY KEY,
    asset           TEXT NOT NULL UNIQUE,
    review_priority INTEGER NOT NULL,
    reason          TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'new',
    signals_json    TEXT NOT NULL DEFAULT '[]',
    first_seen      TEXT NOT NULL,
    latest_seen     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_review_priority ON review_items(status, review_priority DESC);
"""


class ReconStore:
    """Recon-table accessor over one open :class:`Database` connection."""

    def __init__(self, database: Database) -> None:
        self._db = database

    @property
    def conn(self) -> sqlite3.Connection:
        return self._db.conn

    def ensure_schema(self) -> None:
        self.conn.executescript(_RECON_SCHEMA)
        row = self.conn.execute("SELECT value FROM recon_meta WHERE key = 'schema_version'").fetchone()
        current = int(row[0]) if row else 0
        if current > RECON_SCHEMA_VERSION:
            raise RuntimeError(
                f"recon schema version {current} is newer than supported {RECON_SCHEMA_VERSION}"
            )
        self.conn.execute(
            "INSERT INTO recon_meta (key, value) VALUES ('schema_version', ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (str(RECON_SCHEMA_VERSION),),
        )

    # -- runs & stages ---------------------------------------------------------------

    def start_run(self, started_at: str, scope_hash: str | None = None) -> int:
        cur = self.conn.execute(
            "INSERT INTO recon_runs (started_at, status, scope_hash) VALUES (?, 'running', ?)",
            (started_at, scope_hash),
        )
        return int(cur.lastrowid)

    def finish_run(self, run_id: int, finished_at: str, status: str) -> None:
        self.conn.execute(
            "UPDATE recon_runs SET finished_at = ?, status = ? WHERE id = ?",
            (finished_at, status, run_id),
        )

    def set_stage(self, run_id: int, stage: str, status: StageStatus, when: str, detail: str | None = None) -> None:
        column = "finished_at" if status in (StageStatus.COMPLETED, StageStatus.FAILED, StageStatus.SKIPPED) else "started_at"
        self.conn.execute(
            f"""INSERT INTO recon_stages (run_id, stage, status, {column}, detail)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(run_id, stage) DO UPDATE SET status = excluded.status,
                    {column} = excluded.{column}, detail = COALESCE(excluded.detail, recon_stages.detail)""",
            (run_id, stage, status.value, when, detail),
        )

    def stage_status(self, run_id: int, stage: str) -> StageStatus | None:
        row = self.conn.execute(
            "SELECT status FROM recon_stages WHERE run_id = ? AND stage = ?", (run_id, stage)
        ).fetchone()
        return StageStatus(row[0]) if row else None

    def latest_unfinished_run(self) -> int | None:
        row = self.conn.execute(
            "SELECT id FROM recon_runs WHERE status IN ('running', 'failed', 'interrupted') ORDER BY id DESC LIMIT 1"
        ).fetchone()
        return int(row[0]) if row else None

    # -- hosts & discovery -----------------------------------------------------------

    def upsert_host(self, hostname: str, scope_class: ScopeClass, source: str, now: str) -> tuple[int, bool]:
        row = self.conn.execute("SELECT id FROM hosts WHERE hostname = ?", (hostname,)).fetchone()
        if row is None:
            host_id = int(self.conn.execute(
                "INSERT INTO hosts (hostname, scope_class, first_seen, last_seen) VALUES (?, ?, ?, ?)",
                (hostname, scope_class.value, now, now),
            ).lastrowid)
            created = True
        else:
            host_id = int(row[0])
            self.conn.execute(
                "UPDATE hosts SET last_seen = ?, scope_class = ? WHERE id = ?",
                (now, scope_class.value, host_id),
            )
            created = False
        self.conn.execute(
            "INSERT INTO discovery_sources (host_id, source, first_seen) VALUES (?, ?, ?) "
            "ON CONFLICT(host_id, source) DO NOTHING",
            (host_id, source, now),
        )
        return host_id, created

    def host_id(self, hostname: str) -> int | None:
        row = self.conn.execute("SELECT id FROM hosts WHERE hostname = ?", (hostname,)).fetchone()
        return int(row[0]) if row else None

    def all_hosts(self, scope_class: ScopeClass | None = None) -> list[str]:
        if scope_class is None:
            rows = self.conn.execute("SELECT hostname FROM hosts ORDER BY hostname").fetchall()
        else:
            rows = self.conn.execute(
                "SELECT hostname FROM hosts WHERE scope_class = ? ORDER BY hostname", (scope_class.value,)
            ).fetchall()
        return [r[0] for r in rows]

    # -- dns --------------------------------------------------------------------------

    def _load_dns(self, host_id: int, hostname: str) -> DnsRecord | None:
        row = self.conn.execute(
            "SELECT status, a_json, aaaa_json, cname FROM dns_records WHERE host_id = ?", (host_id,)
        ).fetchone()
        if row is None:
            return None
        return DnsRecord(
            hostname=hostname, status=row[0],
            a=tuple(json.loads(row[1])), aaaa=tuple(json.loads(row[2])),
            cname_chain=(row[3],) if row[3] else (),
        )

    def record_dns(self, host_id: int, record: DnsRecord, now: str) -> list[ReconEvent]:
        """Store the DNS snapshot and return the transitions vs the previous one."""
        previous = self._load_dns(host_id, record.hostname)
        events = dns_transitions(previous, record)
        changed = previous is not None and bool(set(events) - {ReconEvent.NEW_SUBDOMAIN})
        self.conn.execute(
            """INSERT INTO dns_records (host_id, status, a_json, aaaa_json, cname, first_seen, last_seen, changed_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(host_id) DO UPDATE SET status = excluded.status, a_json = excluded.a_json,
                   aaaa_json = excluded.aaaa_json, cname = excluded.cname, last_seen = excluded.last_seen,
                   changed_at = CASE WHEN ? THEN excluded.last_seen ELSE dns_records.changed_at END""",
            (host_id, record.status, json.dumps(list(record.a)), json.dumps(list(record.aaaa)),
             record.terminal_cname, now, now, now if changed else None, changed),
        )
        return events

    # -- services ---------------------------------------------------------------------

    def record_service(self, service: Service, now: str) -> list[ReconEvent]:
        row = self.conn.execute(
            "SELECT id, status, service_guess FROM services WHERE host = ? AND port = ? AND protocol = ?",
            (service.host, service.port, service.protocol),
        ).fetchone()
        events: list[ReconEvent] = []
        if row is None:
            self.conn.execute(
                """INSERT INTO services (host, port, protocol, service_guess, banner, source, status, first_seen, last_seen)
                   VALUES (?, ?, ?, ?, ?, ?, 'open', ?, ?)""",
                (service.host, service.port, service.protocol, service.service_guess,
                 service.banner, service.source, now, now),
            )
            events.append(ReconEvent.NEW_OPEN_PORT)
        else:
            if row[1] != "open":
                events.append(ReconEvent.NEW_OPEN_PORT)
            if service.service_guess and row[2] and service.service_guess != row[2]:
                events.append(ReconEvent.SERVICE_CHANGED)
            self.conn.execute(
                "UPDATE services SET status = 'open', last_seen = ?, service_guess = COALESCE(?, service_guess), "
                "banner = COALESCE(?, banner) WHERE id = ?",
                (now, service.service_guess, service.banner, row[0]),
            )
        return events

    def mark_closed_ports(self, host: str, open_ports: Iterable[int], now: str) -> list[int]:
        """Mark previously-open ports not in ``open_ports`` as closed. Returns them."""
        keep = set(open_ports)
        rows = self.conn.execute(
            "SELECT id, port FROM services WHERE host = ? AND status = 'open'", (host,)
        ).fetchall()
        closed = [r[1] for r in rows if r[1] not in keep]
        for row in rows:
            if row[1] not in keep:
                self.conn.execute("UPDATE services SET status = 'closed', last_seen = ? WHERE id = ?", (now, row[0]))
        return closed

    # -- urls -------------------------------------------------------------------------

    def record_url(self, url: UrlRecord, now: str) -> bool:
        row = self.conn.execute("SELECT id FROM urls WHERE url = ?", (url.url,)).fetchone()
        if row is None:
            self.conn.execute(
                """INSERT INTO urls (url, host, path, param_names, source, status_code, scope_class, first_seen, last_seen)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (url.url, url.host, url.path, ",".join(url.param_names), url.source,
                 url.status_code, url.scope_class.value, now, now),
            )
            return True
        self.conn.execute(
            "UPDATE urls SET last_seen = ?, status_code = COALESCE(?, status_code), "
            "source = ? WHERE id = ?",
            (now, url.status_code, url.source, row[0]),
        )
        return False

    # -- javascript -------------------------------------------------------------------

    def record_js(self, url: str, host: str, raw_sha: str, norm_sha: str | None,
                  size: int, source_map: str | None, now: str) -> tuple[int, list[ReconEvent]]:
        row = self.conn.execute(
            "SELECT id, raw_sha256, normalized_sha256, source_map FROM javascript_assets WHERE url = ?", (url,)
        ).fetchone()
        events: list[ReconEvent] = []
        if row is None:
            js_id = int(self.conn.execute(
                """INSERT INTO javascript_assets (url, host, raw_sha256, normalized_sha256, size, source_map, first_seen, last_seen)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (url, host, raw_sha, norm_sha, size, source_map, now, now),
            ).lastrowid)
            events.append(ReconEvent.NEW_JS_FILE)
            if source_map:
                events.append(ReconEvent.NEW_SOURCE_MAP)
            return js_id, events
        js_id = int(row[0])
        baseline = row[2] or row[1]
        current = norm_sha or raw_sha
        changed = baseline != current
        if changed:
            events.append(ReconEvent.JS_CHANGED)
        if source_map and not row[3]:
            events.append(ReconEvent.NEW_SOURCE_MAP)
        self.conn.execute(
            "UPDATE javascript_assets SET raw_sha256 = ?, normalized_sha256 = ?, size = ?, "
            "source_map = COALESCE(?, source_map), last_seen = ?, changed_at = CASE WHEN ? THEN ? ELSE changed_at END "
            "WHERE id = ?",
            (raw_sha, norm_sha, size, source_map, now, changed, now, js_id),
        )
        return js_id, events

    def record_js_findings(self, js_id: int, findings: Iterable[JsFinding], now: str) -> list[JsFinding]:
        """Insert findings, returning the ones that are new for this JS asset."""
        new: list[JsFinding] = []
        for f in findings:
            cur = self.conn.execute(
                "INSERT INTO js_findings (js_id, finding_type, value, confidence, evidence, first_seen) "
                "VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(js_id, finding_type, value) DO NOTHING",
                (js_id, f.finding_type.value, f.value, f.confidence, f.evidence, now),
            )
            if cur.rowcount:
                new.append(f)
        return new

    # -- endpoints & parameters -------------------------------------------------------

    def record_endpoint(self, endpoint: Endpoint, identity: str, now: str) -> bool:
        row = self.conn.execute("SELECT id, param_names, source FROM endpoints WHERE identity = ?", (identity,)).fetchone()
        if row is None:
            self.conn.execute(
                """INSERT INTO endpoints (identity, host, path, method, method_confidence, param_names, source, confidence, first_seen, last_seen)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (identity, endpoint.host, endpoint.path, endpoint.method, endpoint.method_confidence.value,
                 ",".join(endpoint.param_names), endpoint.source, endpoint.confidence, now, now),
            )
            return True
        params = ",".join(dict.fromkeys([*filter(None, row[1].split(",")), *endpoint.param_names]))
        sources = ",".join(dict.fromkeys([*filter(None, (row[2] or "").split(",")), *endpoint.source.split(",")]))
        self.conn.execute(
            "UPDATE endpoints SET param_names = ?, source = ?, last_seen = ? WHERE id = ?",
            (params, sources, now, row[0]),
        )
        return False

    def record_parameter(self, param: Parameter, now: str) -> bool:
        """Insert or refresh a parameter. Returns True when it is newly seen."""
        row = self.conn.execute(
            "SELECT id FROM parameters WHERE name = ? AND location = ? AND endpoint_identity IS ?",
            (param.name, param.location.value, param.endpoint_identity),
        ).fetchone()
        if row is None:
            self.conn.execute(
                """INSERT INTO parameters (name, location, endpoint_identity, source, confidence, first_seen, last_seen)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (param.name, param.location.value, param.endpoint_identity, param.source, param.confidence, now, now),
            )
            return True
        self.conn.execute(
            "UPDATE parameters SET last_seen = ?, source = ?, confidence = MAX(confidence, ?) WHERE id = ?",
            (now, param.source, param.confidence, row[0]),
        )
        return False

    # -- technologies & favicons ------------------------------------------------------

    def record_technology(self, host: str, tech: Technology, now: str) -> list[ReconEvent]:
        row = self.conn.execute(
            "SELECT id, version, removed_at FROM technologies WHERE host = ? AND name = ?", (host, tech.name)
        ).fetchone()
        events: list[ReconEvent] = []
        if row is None:
            self.conn.execute(
                "INSERT INTO technologies (host, name, version, confidence, evidence, first_seen, last_seen) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (host, tech.name, tech.version, tech.confidence, tech.evidence, now, now),
            )
            events.append(ReconEvent.TECHNOLOGY_ADDED)
        else:
            if tech.version and row[1] and tech.version != row[1]:
                events.append(ReconEvent.VERSION_CHANGED)
            if row[2] is not None:
                events.append(ReconEvent.TECHNOLOGY_ADDED)  # reappeared
            self.conn.execute(
                "UPDATE technologies SET version = COALESCE(?, version), confidence = MAX(confidence, ?), "
                "evidence = ?, last_seen = ?, removed_at = NULL WHERE id = ?",
                (tech.version, tech.confidence, tech.evidence, now, row[0]),
            )
        return events

    def record_favicon(self, host: str, sha256: str, now: str) -> list[ReconEvent]:
        current = self.conn.execute(
            "SELECT sha256 FROM favicons WHERE host = ? AND is_current = 1", (host,)
        ).fetchone()
        events: list[ReconEvent] = []
        if current is not None and current[0] != sha256:
            self.conn.execute("UPDATE favicons SET is_current = 0 WHERE host = ?", (host,))
            events.append(ReconEvent.FAVICON_CHANGED)
        self.conn.execute(
            "INSERT INTO favicons (host, sha256, is_current, first_seen, last_seen) VALUES (?, ?, 1, ?, ?) "
            "ON CONFLICT(host, sha256) DO UPDATE SET is_current = 1, last_seen = excluded.last_seen",
            (host, sha256, now, now),
        )
        return events

    # -- signals & review queue -------------------------------------------------------

    def add_signal(self, run_id: int | None, signal: ReconSignal, now: str) -> None:
        self.conn.execute(
            "INSERT INTO recon_signals (run_id, rule_id, asset, reason, review_priority, evidence, detected_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (run_id, signal.rule_id, signal.asset, signal.reason, signal.review_priority,
             json.dumps(signal.evidence, sort_keys=True), now),
        )

    def upsert_review_item(self, asset: str, priority: int, reason: str, signals: Sequence[str], now: str) -> None:
        row = self.conn.execute("SELECT id, review_priority, status FROM review_items WHERE asset = ?", (asset,)).fetchone()
        if row is None:
            self.conn.execute(
                "INSERT INTO review_items (asset, review_priority, reason, status, signals_json, first_seen, latest_seen) "
                "VALUES (?, ?, ?, 'new', ?, ?, ?)",
                (asset, priority, reason, json.dumps(list(signals)), now, now),
            )
            return
        # Reflect the CURRENT run's standing (not an all-time max), so a once-new
        # asset does not sit at the top forever. first_seen is preserved; an item
        # that was dismissed/resolved reopens when fresh signals appear for it.
        status = "new" if row[2] in ("dismissed", "resolved") else row[2]
        self.conn.execute(
            "UPDATE review_items SET review_priority = ?, reason = ?, status = ?, signals_json = ?, latest_seen = ? WHERE id = ?",
            (priority, reason, status, json.dumps(list(signals)), now, row[0]),
        )

    def review_queue(self, statuses: Sequence[str] | None = None, limit: int = 100) -> list[sqlite3.Row]:
        if statuses:
            placeholders = ",".join("?" for _ in statuses)
            sql = (f"SELECT * FROM review_items WHERE status IN ({placeholders}) "
                   "ORDER BY review_priority DESC, latest_seen DESC LIMIT ?")
            return self.conn.execute(sql, (*statuses, limit)).fetchall()
        return self.conn.execute(
            "SELECT * FROM review_items ORDER BY review_priority DESC, latest_seen DESC LIMIT ?", (limit,)
        ).fetchall()

    def set_review_status(self, asset: str, status: str, now: str) -> bool:
        cur = self.conn.execute(
            "UPDATE review_items SET status = ?, latest_seen = ? WHERE asset = ?", (status, now, asset)
        )
        return bool(cur.rowcount)

    def latest_http(self, host: str) -> tuple[int | None, str | None]:
        """Latest monitoring observation (status, title) for a host's base asset."""
        row = self.conn.execute(
            "SELECT o.status_code, o.title FROM observations o JOIN assets a ON a.id = o.asset_id "
            "WHERE a.hostname = ? ORDER BY o.id DESC LIMIT 1",
            (host,),
        ).fetchone()
        return (row[0], row[1]) if row else (None, None)

    def latest_content_change(self, host: str) -> tuple[str | None, int]:
        """Most recent monitoring content-change (magnitude, review_priority) for a host."""
        row = self.conn.execute(
            "SELECT c.details, c.review_priority FROM changes c JOIN assets a ON a.id = c.asset_id "
            "WHERE a.hostname = ? AND c.change_type LIKE 'content_changed%' ORDER BY c.id DESC LIMIT 1",
            (host,),
        ).fetchone()
        if row is None:
            return None, 0
        try:
            magnitude = json.loads(row[0]).get("magnitude")
        except (ValueError, TypeError):
            magnitude = None
        return magnitude, int(row[1])

    def latest_interesting_transition(self, host: str) -> tuple[int, str | None, str | None]:
        """Most recent *interesting* monitoring HTTP transition (not content) for a host.

        Returns (review_priority, change_type, reason). This is how the monitoring
        engine's status/availability findings (e.g. 403/404 -> 200) reach recon.
        """
        row = self.conn.execute(
            "SELECT c.review_priority, c.change_type, c.reason FROM changes c JOIN assets a ON a.id = c.asset_id "
            "WHERE a.hostname = ? AND c.interesting = 1 AND c.change_type NOT LIKE 'content_changed%' "
            "ORDER BY c.id DESC LIMIT 1",
            (host,),
        ).fetchone()
        return (int(row[0]), row[1], row[2]) if row else (0, None, None)

    def host_change_ratio(self, host: str) -> float | None:
        """Monitoring change_ratio for a host's base asset, for noise-aware ranking."""
        row = self.conn.execute(
            "SELECT content_comparisons, content_change_count FROM assets "
            "WHERE hostname = ? ORDER BY content_comparisons DESC LIMIT 1",
            (host,),
        ).fetchone()
        if row is None or not row[0]:
            return None
        return row[1] / row[0]
