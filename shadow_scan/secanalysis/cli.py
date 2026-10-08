"""CLI for the security-analysis subsystem: the ``analyze`` and ``findings`` commands."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sqlite3
from collections.abc import Sequence
from pathlib import Path

from ..config import ScanConfig
from ..database import Database
from ..utils import configure_logging, utc_now_iso
from .ai import AIConfig
from .models import EndpointInfo, FindingStatus
from .pipeline import SecurityComponents, SecurityConfig, SecurityPipeline
from .profiles import default_profile, load_profile
from .scope_compat import build_scope
from .sec_db import SecurityStore

logger = logging.getLogger("shadow_scan.secanalysis")

EXIT_OK, EXIT_FAILURE, EXIT_INTERRUPTED = 0, 1, 130
_FINDING_STATUSES = tuple(s.value for s in FindingStatus)


def _scheme_port(scope, host: str, default_scheme: str) -> tuple[str, int | None]:
    """Derive the scheme/port to probe a host on, honoring any scope URL constraint."""
    from ..utils import InvalidTargetError, normalize_target
    try:
        target = normalize_target(scope.monitor_target(host))
    except InvalidTargetError:
        return default_scheme, None
    return (target.scheme or default_scheme), target.port


def _load_endpoints_from_db(database: Path, scheme: str, scope) -> list[EndpointInfo]:
    """Build EndpointInfo from the recon endpoints table, falling back to monitored hosts.

    The scheme/port to probe each host on comes from the scope (so a port-scoped
    program hits the right port), not from the recon row which omits it.
    """
    endpoints: list[EndpointInfo] = []
    port_cache: dict[str, tuple[str, int | None]] = {}

    def sp(host: str) -> tuple[str, int | None]:
        if host not in port_cache:
            port_cache[host] = _scheme_port(scope, host, scheme)
        return port_cache[host]

    with Database(database) as db:
        conn = db.conn
        if _table_exists(conn, "endpoints"):
            for row in conn.execute(
                "SELECT identity, host, path, method, method_confidence, param_names, source FROM endpoints"
            ):
                params = tuple(p for p in (row[5] or "").split(",") if p)
                host_scheme, host_port = sp(row[1])
                endpoints.append(EndpointInfo(
                    host=row[1], path=row[2], method=row[3] or "UNKNOWN",
                    method_confidence=row[4] or "unknown", param_names=params,
                    source=row[6] or "recon", identity=row[0], scheme=host_scheme, port=host_port,
                ))
        if not endpoints and _table_exists(conn, "assets"):
            for row in conn.execute("SELECT DISTINCT hostname FROM assets"):
                host = row[0]
                host_scheme, host_port = sp(host)
                endpoints.append(EndpointInfo(host=host, path="/", method="GET",
                                              identity=f"GET {host}/", scheme=host_scheme, port=host_port))
    return endpoints


def _table_exists(conn: sqlite3.Connection, name: str) -> bool:
    return conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone() is not None


def run_analyze(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="shadow_scan analyze",
        description="Bounded, non-destructive security analysis of the recon inventory. "
                    "Authorized targets only; never exploitation/brute-force/DoS.")
    parser.add_argument("--database", "-d", type=Path, default=Path("shadowscan.db"), help="SQLite database")
    parser.add_argument("--program", "-p", type=Path, help="program profile YAML (programs/<name>.yaml)")
    parser.add_argument("--scope", "-s", type=Path, help="scope file (defaults to program scope_roots)")
    parser.add_argument("--scheme", default="https", choices=("https", "http"), help="scheme for endpoint URLs")
    parser.add_argument("--passive-only", action="store_true", help="never issue active requests")
    parser.add_argument("--no-ai", action="store_true", help="skip the AI hypothesis stage")
    parser.add_argument("--auth-context", action="append", default=[],
                        help="auth-profile name to use for read-only access-control differential (repeatable)")
    parser.add_argument("--resume", action="store_true", help="resume the last unfinished security run")
    parser.add_argument("--insecure", action="store_true", help="skip TLS verification")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args(argv)
    configure_logging(args.verbose)

    if not args.database.exists():
        logger.error("Database %s not found; run 'shadow_scan recon' first", args.database)
        return EXIT_FAILURE

    program = default_profile()
    if args.program:
        try:
            program = load_profile(args.program)
        except (OSError, ValueError, RuntimeError) as exc:
            logger.error("Cannot load program profile %s: %s", args.program, exc)
            return EXIT_FAILURE

    scope_lines: list[str]
    if args.scope:
        try:
            scope_lines = args.scope.read_text(encoding="utf-8-sig").splitlines()
        except OSError as exc:
            logger.error("Cannot read scope file %s: %s", args.scope, exc)
            return EXIT_FAILURE
    else:
        scope_lines = list(program.scope_roots) + [f"!{h}" for h in program.excluded_hosts]
    scope = build_scope(scope_lines)

    endpoints = _load_endpoints_from_db(args.database, args.scheme, scope)
    if not endpoints:
        logger.warning("No endpoints found in %s; nothing to analyze", args.database)
        return EXIT_OK
    # Only analyze in-scope endpoints.
    endpoints = [e for e in endpoints if scope.classify_host(e.host).value == "in_scope"]
    logger.info("Analyzing %d in-scope endpoints", len(endpoints))

    from .models import TestingPolicy
    if args.passive_only:
        program.global_mode = TestingPolicy.PASSIVE_ONLY

    scan = ScanConfig(database_path=args.database, concurrency=program.active_concurrency,
                      request_timeout=10.0, total_timeout=30.0, verify_tls=not args.insecure)
    config = SecurityConfig(
        scope=scope, scan_config=scan, program=program,
        ai=AIConfig(enabled=not args.no_ai), enable_active=not args.passive_only,
        enable_ai=not args.no_ai, auth_contexts=tuple(args.auth_context),
    )
    pipeline = SecurityPipeline(config, endpoints, SecurityComponents())
    try:
        run_id = asyncio.run(pipeline.run(resume=args.resume))
    except KeyboardInterrupt:
        logger.warning("Security analysis interrupted; resume with --resume")
        return EXIT_INTERRUPTED

    print(_format_findings(str(args.database), ["new", "reviewing"], limit=15, detail=True), flush=True)
    logger.info("Security run #%s complete. Triage with: shadow_scan findings --database %s", run_id, args.database)
    return EXIT_OK


def _format_findings(database: str, statuses: Sequence[str] | None, limit: int, detail: bool) -> str:
    with Database(database) as db:
        store = SecurityStore(db)
        store.ensure_schema()
        rows = store.findings(statuses, limit)
        if not rows:
            return "No security findings."
        ai_by_asset: dict[str, list] = {}
        lines = ["Security findings", ""]
        for row in rows:
            tag = "" if row["status"] == "new" else f"  ({row['status']})"
            lines.append(f"[{row['review_priority']:>3}] {row['title']}{tag}")
            lines.append(f"      {row['asset']}  {row['endpoint'] or ''}  [{row['validation_state']}]")
            if detail:
                for ev in store.evidence_for(row["id"])[:4]:
                    lines.append(f"      - {ev['summary']}")
                hyps = ai_by_asset.get(row["asset"])
                if hyps is None:
                    hyps = store.ai_for_asset(row["asset"])
                    ai_by_asset[row["asset"]] = hyps
                for h in hyps[:1]:
                    lines.append(f"      AI: {h.get('title', '')} (confidence {h.get('confidence', 0)})")
                    for t in h.get("manual_tests", [])[:1]:
                        lines.append(f"          suggested: {t}")
                lines.append(f"      id={row['id']}  source={row['source']}")
        return "\n".join(lines)


def run_findings(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="shadow_scan findings",
        description="Inspect and triage security findings (show / mark status / notes).")
    parser.add_argument("--database", "-d", type=Path, default=Path("shadowscan.db"))
    parser.add_argument("--status", action="append", choices=_FINDING_STATUSES,
                        help="filter by status (repeatable); default shows active findings")
    parser.add_argument("--all", action="store_true", help="include dismissed/resolved/false-positive")
    parser.add_argument("--limit", type=int, default=50)
    parser.add_argument("--show", type=int, metavar="ID", help="show one finding in full (with manual package)")
    parser.add_argument("--set", nargs=2, metavar=("ID", "STATUS"), help="set a finding's status")
    args = parser.parse_args(argv)
    configure_logging(False)

    if not args.database.exists():
        logger.error("Database %s not found; run 'shadow_scan analyze' first", args.database)
        return EXIT_FAILURE

    if args.set:
        fid_s, status = args.set
        if status not in _FINDING_STATUSES:
            logger.error("Invalid status %r; choose from %s", status, ", ".join(_FINDING_STATUSES))
            return EXIT_FAILURE
        with Database(args.database) as db:
            store = SecurityStore(db)
            store.ensure_schema()
            with db.transaction():
                changed = store.set_finding_status(int(fid_s), status)
        print(f"finding {fid_s}: status set to {status}" if changed else f"finding {fid_s}: not found")
        return EXIT_OK

    if args.show is not None:
        return _show_finding(args.database, args.show)

    statuses = args.status or (None if args.all else ["new", "reviewing", "confirmed"])
    print(_format_findings(str(args.database), statuses, args.limit, detail=True), flush=True)
    return EXIT_OK


def _show_finding(database: Path, fid: int) -> int:
    with Database(database) as db:
        store = SecurityStore(db)
        store.ensure_schema()
        rows = store.findings(None, limit=10_000)
        row = next((r for r in rows if r["id"] == fid), None)
        if row is None:
            logger.error("finding %d not found", fid)
            return EXIT_FAILURE
        lines = [f"[{row['review_priority']}] {row['title']}", f"asset: {row['asset']}",
                 f"endpoint: {row['endpoint']}  parameter: {row['parameter']}",
                 f"category: {row['category']}  status: {row['status']}  validation: {row['validation_state']}",
                 f"confidence: {row['confidence']}  severity_hint: {row['severity_hint']}  source: {row['source']}",
                 "", "Evidence:"]
        for ev in store.evidence_for(fid):
            lines.append(f"  - [{ev['kind']}] {ev['summary']}")
        hyps = store.ai_for_asset(row["asset"])
        if hyps:
            lines += ["", "AI hypotheses (advisory; not vulnerabilities):"]
            for h in hyps[:3]:
                lines.append(f"  - {h.get('title')} (confidence {h.get('confidence')})")
                for t in h.get("manual_tests", [])[:3]:
                    lines.append(f"      test: {t}")
        pkgs = db.conn.execute(
            "SELECT package FROM manual_validation_items WHERE finding_id=?", (fid,)).fetchall()
        if pkgs:
            lines += ["", "Manual validation package:"]
            lines.append(json.dumps(json.loads(pkgs[0][0]), indent=2))
    print("\n".join(lines), flush=True)
    return EXIT_OK
