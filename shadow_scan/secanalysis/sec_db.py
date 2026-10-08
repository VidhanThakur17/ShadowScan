"""Security-analysis persistence, layered on the existing single-writer Database.

Adds security tables additively (tracked by ``sec_meta``), reusing the one
connection/WAL/single-writer model. Includes the attack-path graph as two
relational tables (nodes/edges) — no graph database. Authentication secrets are
never stored: ``auth_profiles_metadata`` holds only identifiers and the env-var
*names* a profile references.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable, Sequence

from ..database import Database
from . import SECURITY_SCHEMA_VERSION
from .findings import finalize, merge
from .models import Finding, StageStatus

_SCHEMA = """
CREATE TABLE IF NOT EXISTS sec_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS sec_runs (
    id INTEGER PRIMARY KEY, started_at TEXT NOT NULL, finished_at TEXT, status TEXT NOT NULL, program TEXT
);
CREATE TABLE IF NOT EXISTS sec_stages (
    run_id INTEGER NOT NULL REFERENCES sec_runs(id) ON DELETE CASCADE,
    stage TEXT NOT NULL, status TEXT NOT NULL, started_at TEXT, finished_at TEXT, detail TEXT,
    PRIMARY KEY (run_id, stage)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS security_checks (
    id INTEGER PRIMARY KEY, run_id INTEGER REFERENCES sec_runs(id) ON DELETE SET NULL,
    check_id TEXT NOT NULL, asset TEXT NOT NULL, endpoint TEXT, policy TEXT NOT NULL,
    policy_reason TEXT, executed INTEGER NOT NULL DEFAULT 0, decided_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sec_checks_asset ON security_checks(asset);

CREATE TABLE IF NOT EXISTS security_findings (
    id INTEGER PRIMARY KEY, dedup_key TEXT NOT NULL UNIQUE, check_id TEXT NOT NULL,
    asset TEXT NOT NULL, endpoint TEXT, parameter TEXT, category TEXT NOT NULL, title TEXT NOT NULL,
    confidence REAL NOT NULL DEFAULT 0.5, severity_hint TEXT, review_priority INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'new', validation_state TEXT NOT NULL DEFAULT 'observed',
    source TEXT, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sec_findings_priority ON security_findings(status, review_priority DESC);
CREATE INDEX IF NOT EXISTS idx_sec_findings_asset ON security_findings(asset);

CREATE TABLE IF NOT EXISTS finding_evidence (
    id INTEGER PRIMARY KEY, finding_id INTEGER NOT NULL REFERENCES security_findings(id) ON DELETE CASCADE,
    kind TEXT NOT NULL, summary TEXT NOT NULL, data TEXT NOT NULL DEFAULT '{}', source TEXT,
    UNIQUE (finding_id, kind, summary)
);

CREATE TABLE IF NOT EXISTS auth_profiles_metadata (
    name TEXT PRIMARY KEY, host TEXT NOT NULL, header_name TEXT, token_env TEXT, cookie_env TEXT, description TEXT
);

CREATE TABLE IF NOT EXISTS validation_runs (
    id INTEGER PRIMARY KEY, finding_id INTEGER REFERENCES security_findings(id) ON DELETE CASCADE,
    kind TEXT NOT NULL, result TEXT NOT NULL, detail TEXT, created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ai_analyses (
    id INTEGER PRIMARY KEY, evidence_fingerprint TEXT NOT NULL UNIQUE, asset TEXT NOT NULL,
    endpoint TEXT, provider TEXT, hypotheses TEXT NOT NULL, created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS manual_validation_items (
    id INTEGER PRIMARY KEY, finding_id INTEGER REFERENCES security_findings(id) ON DELETE CASCADE,
    asset TEXT NOT NULL, endpoint TEXT, package TEXT NOT NULL, created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS graph_nodes (
    id INTEGER PRIMARY KEY, node_type TEXT NOT NULL, key TEXT NOT NULL,
    label TEXT, attrs TEXT NOT NULL DEFAULT '{}', first_seen TEXT NOT NULL,
    UNIQUE (node_type, key)
);
CREATE INDEX IF NOT EXISTS idx_graph_nodes_type ON graph_nodes(node_type);

CREATE TABLE IF NOT EXISTS graph_edges (
    id INTEGER PRIMARY KEY, src INTEGER NOT NULL REFERENCES graph_nodes(id) ON DELETE CASCADE,
    dst INTEGER NOT NULL REFERENCES graph_nodes(id) ON DELETE CASCADE,
    edge_type TEXT NOT NULL, attrs TEXT NOT NULL DEFAULT '{}',
    UNIQUE (src, dst, edge_type)
);
CREATE INDEX IF NOT EXISTS idx_graph_edges_src ON graph_edges(src, edge_type);
CREATE INDEX IF NOT EXISTS idx_graph_edges_dst ON graph_edges(dst, edge_type);
"""


class SecurityStore:
    def __init__(self, database: Database) -> None:
        self._db = database

    @property
    def conn(self) -> sqlite3.Connection:
        return self._db.conn

    def ensure_schema(self) -> None:
        self.conn.executescript(_SCHEMA)
        row = self.conn.execute("SELECT value FROM sec_meta WHERE key='schema_version'").fetchone()
        current = int(row[0]) if row else 0
        if current > SECURITY_SCHEMA_VERSION:
            raise RuntimeError(f"security schema {current} newer than supported {SECURITY_SCHEMA_VERSION}")
        self.conn.execute(
            "INSERT INTO sec_meta(key,value) VALUES('schema_version',?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (str(SECURITY_SCHEMA_VERSION),),
        )

    # -- runs / stages ---------------------------------------------------------------

    def start_run(self, started_at: str, program: str | None) -> int:
        return int(self.conn.execute(
            "INSERT INTO sec_runs(started_at,status,program) VALUES(?,?,?)",
            (started_at, "running", program)).lastrowid)

    def finish_run(self, run_id: int, finished_at: str, status: str) -> None:
        self.conn.execute("UPDATE sec_runs SET finished_at=?, status=? WHERE id=?", (finished_at, status, run_id))

    def set_stage(self, run_id: int, stage: str, status: StageStatus, when: str, detail: str | None = None) -> None:
        col = "finished_at" if status in (StageStatus.COMPLETED, StageStatus.FAILED, StageStatus.SKIPPED) else "started_at"
        self.conn.execute(
            f"INSERT INTO sec_stages(run_id,stage,status,{col},detail) VALUES(?,?,?,?,?) "
            f"ON CONFLICT(run_id,stage) DO UPDATE SET status=excluded.status, {col}=excluded.{col}, "
            "detail=COALESCE(excluded.detail,sec_stages.detail)",
            (run_id, stage, status.value, when, detail))

    def stage_status(self, run_id: int, stage: str) -> StageStatus | None:
        row = self.conn.execute("SELECT status FROM sec_stages WHERE run_id=? AND stage=?", (run_id, stage)).fetchone()
        return StageStatus(row[0]) if row else None

    def latest_unfinished_run(self) -> int | None:
        row = self.conn.execute(
            "SELECT id FROM sec_runs WHERE status IN ('running','failed','interrupted') ORDER BY id DESC LIMIT 1"
        ).fetchone()
        return int(row[0]) if row else None

    # -- policy decisions ------------------------------------------------------------

    def record_check(self, run_id: int | None, check_id: str, asset: str, endpoint: str | None,
                     policy: str, reason: str, executed: bool, now: str) -> None:
        self.conn.execute(
            "INSERT INTO security_checks(run_id,check_id,asset,endpoint,policy,policy_reason,executed,decided_at) "
            "VALUES(?,?,?,?,?,?,?,?)", (run_id, check_id, asset, endpoint, policy, reason, int(executed), now))

    # -- findings (dedup-aware upsert) -----------------------------------------------

    def upsert_finding(self, finding: Finding, now: str) -> int:
        finalize(finding)
        row = self.conn.execute(
            "SELECT id, confidence, review_priority, validation_state FROM security_findings WHERE dedup_key=?",
            (finding.dedup_key,)).fetchone()
        if row is None:
            fid = int(self.conn.execute(
                """INSERT INTO security_findings(dedup_key,check_id,asset,endpoint,parameter,category,title,
                       confidence,severity_hint,review_priority,status,validation_state,source,first_seen,last_seen)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (finding.dedup_key, finding.check_id, finding.asset, finding.endpoint, finding.parameter,
                 finding.category, finding.title, finding.confidence, finding.severity_hint,
                 finding.review_priority, finding.status.value, finding.validation_state.value,
                 finding.source, now, now)).lastrowid)
        else:
            fid = int(row[0])
            self.conn.execute(
                "UPDATE security_findings SET confidence=MAX(confidence,?), review_priority=MAX(review_priority,?), "
                "last_seen=?, source=?, title=? WHERE id=?",
                (finding.confidence, finding.review_priority, now, finding.source, finding.title, fid))
        for ev in finding.evidence:
            self.conn.execute(
                "INSERT INTO finding_evidence(finding_id,kind,summary,data,source) VALUES(?,?,?,?,?) "
                "ON CONFLICT(finding_id,kind,summary) DO NOTHING",
                (fid, ev.kind, ev.summary, json.dumps(ev.data, ensure_ascii=False), ev.source))
        return fid

    def set_finding_status(self, finding_id: int, status: str) -> bool:
        return bool(self.conn.execute(
            "UPDATE security_findings SET status=? WHERE id=?", (status, finding_id)).rowcount)

    def findings(self, statuses: Sequence[str] | None = None, limit: int = 100) -> list[sqlite3.Row]:
        if statuses:
            ph = ",".join("?" for _ in statuses)
            return self.conn.execute(
                f"SELECT * FROM security_findings WHERE status IN ({ph}) ORDER BY review_priority DESC, id DESC LIMIT ?",
                (*statuses, limit)).fetchall()
        return self.conn.execute(
            "SELECT * FROM security_findings ORDER BY review_priority DESC, id DESC LIMIT ?", (limit,)).fetchall()

    def evidence_for(self, finding_id: int) -> list[sqlite3.Row]:
        return self.conn.execute("SELECT kind,summary,data,source FROM finding_evidence WHERE finding_id=?",
                                 (finding_id,)).fetchall()

    # -- ai analyses (fingerprint cache) ---------------------------------------------

    def ai_cached(self, fingerprint: str) -> dict | None:
        row = self.conn.execute("SELECT hypotheses FROM ai_analyses WHERE evidence_fingerprint=?",
                                (fingerprint,)).fetchone()
        return json.loads(row[0]) if row else None

    def store_ai(self, fingerprint: str, asset: str, endpoint: str | None, provider: str,
                 hypotheses: list, now: str) -> None:
        self.conn.execute(
            "INSERT INTO ai_analyses(evidence_fingerprint,asset,endpoint,provider,hypotheses,created_at) "
            "VALUES(?,?,?,?,?,?) ON CONFLICT(evidence_fingerprint) DO UPDATE SET hypotheses=excluded.hypotheses",
            (fingerprint, asset, endpoint, provider, json.dumps(hypotheses, ensure_ascii=False), now))

    def ai_for_asset(self, asset: str) -> list[dict]:
        rows = self.conn.execute("SELECT hypotheses FROM ai_analyses WHERE asset=?", (asset,)).fetchall()
        out: list[dict] = []
        for row in rows:
            try:
                out.extend(json.loads(row[0]))
            except (ValueError, TypeError):
                continue
        return out

    # -- manual validation packages --------------------------------------------------

    def add_manual_package(self, finding_id: int | None, asset: str, endpoint: str | None,
                           package: dict, now: str) -> None:
        self.conn.execute(
            "INSERT INTO manual_validation_items(finding_id,asset,endpoint,package,created_at) VALUES(?,?,?,?,?)",
            (finding_id, asset, endpoint, json.dumps(package, ensure_ascii=False), now))

    # -- auth profile metadata (identifiers only, never secrets) ---------------------

    def record_auth_profile(self, name: str, host: str, header_name: str,
                            token_env: str | None, cookie_env: str | None, description: str) -> None:
        self.conn.execute(
            "INSERT INTO auth_profiles_metadata(name,host,header_name,token_env,cookie_env,description) "
            "VALUES(?,?,?,?,?,?) ON CONFLICT(name) DO UPDATE SET host=excluded.host, "
            "header_name=excluded.header_name, token_env=excluded.token_env, cookie_env=excluded.cookie_env",
            (name, host, header_name, token_env, cookie_env, description))

    # -- attack-path graph -----------------------------------------------------------

    def node(self, node_type: str, key: str, label: str | None = None, attrs: dict | None = None,
             now: str = "") -> int:
        row = self.conn.execute("SELECT id FROM graph_nodes WHERE node_type=? AND key=?",
                                (node_type, key)).fetchone()
        if row is not None:
            return int(row[0])
        return int(self.conn.execute(
            "INSERT INTO graph_nodes(node_type,key,label,attrs,first_seen) VALUES(?,?,?,?,?)",
            (node_type, key, label or key, json.dumps(attrs or {}), now)).lastrowid)

    def edge(self, src: int, dst: int, edge_type: str, attrs: dict | None = None) -> None:
        self.conn.execute(
            "INSERT INTO graph_edges(src,dst,edge_type,attrs) VALUES(?,?,?,?) "
            "ON CONFLICT(src,dst,edge_type) DO NOTHING",
            (src, dst, edge_type, json.dumps(attrs or {})))

    def neighbors(self, node_type: str, key: str, edge_type: str | None = None) -> list[sqlite3.Row]:
        base = ("SELECT n2.node_type, n2.key, e.edge_type FROM graph_nodes n1 "
                "JOIN graph_edges e ON e.src=n1.id JOIN graph_nodes n2 ON n2.id=e.dst "
                "WHERE n1.node_type=? AND n1.key=?")
        params: list = [node_type, key]
        if edge_type:
            base += " AND e.edge_type=?"
            params.append(edge_type)
        return self.conn.execute(base, params).fetchall()

    def nodes_pointing_to(self, node_type: str, key: str, edge_type: str) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT n1.node_type, n1.key FROM graph_nodes n2 JOIN graph_edges e ON e.dst=n2.id "
            "JOIN graph_nodes n1 ON n1.id=e.src WHERE n2.node_type=? AND n2.key=? AND e.edge_type=?",
            (node_type, key, edge_type)).fetchall()
