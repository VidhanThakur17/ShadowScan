"""CLI for continuous operations: program, run, db, finding, feedback/ignore/baseline."""

from __future__ import annotations

import argparse
import asyncio
import logging
from collections.abc import Sequence
from pathlib import Path

from ..database import Database
from ..utils import configure_logging, utc_now_iso
from . import maintenance as maint
from .opsdb import OpsStore
from .runner import RunnerComponents, UnifiedRunner
from .workspace import WorkspaceManager, validate_config

logger = logging.getLogger("shadow_scan.ops")
EXIT_OK, EXIT_FAILURE, EXIT_INTERRUPTED = 0, 1, 130


def _mgr(base: str | None) -> WorkspaceManager:
    return WorkspaceManager(base or ".")


# --- program -------------------------------------------------------------------------

def run_program(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(prog="shadowscan program", description="Manage program workspaces.")
    parser.add_argument("action", choices=("list", "create", "show", "validate", "run", "stats", "archive"))
    parser.add_argument("program", nargs="?")
    parser.add_argument("--base", help="workspace base directory (default: current directory)")
    parser.add_argument("--name"); parser.add_argument("--platform", default="generic")
    parser.add_argument("--force", action="store_true"); parser.add_argument("--resume", action="store_true")
    parser.add_argument("--insecure", action="store_true"); parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args(argv)
    configure_logging(args.verbose)
    mgr = _mgr(args.base)

    if args.action == "list":
        progs = mgr.list_programs()
        print("\n".join(progs) if progs else "No programs. Create one with: shadowscan program create <id>")
        return EXIT_OK
    if not args.program:
        logger.error("program id required for '%s'", args.action)
        return EXIT_FAILURE
    if args.action == "create":
        if mgr.exists(args.program) and not args.force:
            logger.error("program %s already exists (use --force to overwrite config)", args.program)
            return EXIT_FAILURE
        ws = mgr.create(args.program, name=args.name, platform=args.platform)
        print(f"Created program workspace: {ws.config_dir}\nRuntime: {ws.runtime_dir}\n"
              f"Edit {ws.config_dir / 'program.yaml'} and copy auth.example.yaml -> auth.yaml (git-ignored).")
        return EXIT_OK
    if not mgr.exists(args.program):
        logger.error("program %s not found", args.program)
        return EXIT_FAILURE
    config = mgr.load(args.program)
    if args.action == "show":
        print(f"Program: {config.program_id} ({config.name})  platform={config.platform}")
        print(f"Scope: {', '.join(config.scope_roots)}")
        print(f"Mode: {config.profile.global_mode.value}  methods={sorted(config.profile.allowed_methods)}")
        print(f"Stages: {', '.join(config.enabled_stages)}")
        print(f"Notify: min_priority={config.notify_min_priority} providers={config.notify_providers}")
        print(f"Auth profiles: {', '.join(config.profile.auth_profiles) or '(none)'}")
        return EXIT_OK
    if args.action == "validate":
        issues = validate_config(config)
        if not issues:
            print("Configuration valid.")
            return EXIT_OK
        for i in issues:
            print(f"[{i.severity.upper()}] {i.message}")
        return EXIT_FAILURE if any(i.severity == "error" for i in issues) else EXIT_OK
    if args.action == "run":
        issues = [i for i in validate_config(config) if i.severity == "error"]
        if issues:
            logger.error("Refusing to run: %s", "; ".join(i.message for i in issues))
            return EXIT_FAILURE
        ws = mgr.workspace(args.program)
        runner = UnifiedRunner(ws, config, RunnerComponents(), force_lock=args.force,
                               resume=args.resume, verify_tls=not args.insecure)
        try:
            result = asyncio.run(runner.run())
        except KeyboardInterrupt:
            logger.warning("Interrupted; resume with --resume")
            return EXIT_INTERRUPTED
        print(_format_run_summary(config.program_id, result))
        return EXIT_OK if result.status == "completed" else EXIT_FAILURE
    if args.action == "stats":
        ws = mgr.workspace(args.program)
        if not ws.db_path.exists():
            logger.error("no runtime database yet; run the program first")
            return EXIT_FAILURE
        with Database(ws.db_path) as db:
            st = maint.stats(db)
            print(f"Program {args.program} — DB {st.size_bytes:,} bytes")
            for table in ("hosts", "endpoints", "urls", "security_findings", "ops_finding_state"):
                if table in st.tables:
                    print(f"  {table:<22}{st.tables[table]:>8,}")
        return EXIT_OK
    if args.action == "archive":
        ws = mgr.workspace(args.program)
        if ws.db_path.exists():
            dest = ws.exports_dir / f"archive-{utc_now_iso().replace(':', '')[:15]}.db"
            with Database(ws.db_path) as db:
                maint.backup(db, dest)
            print(f"Archived program DB to {dest}")
        else:
            print("Nothing to archive (no runtime database).")
        return EXIT_OK
    return EXIT_FAILURE


def _format_run_summary(program: str, result) -> str:
    s = result.summary
    lines = [f"ShadowScan — {program}", "", f"Run status: {result.status}", ""]
    for label, key in (("Hosts known", "hosts_known"), ("Resolving", "hosts_resolving"),
                       ("URLs", "urls"), ("JS assets", "js_assets"), ("Endpoints", "endpoints"),
                       ("Security findings", "security_findings"),
                       ("Manual review required", "manual_review_required"),
                       ("Validated non-destructively", "validated_non_destructively"),
                       ("Regressions", "regressions"), ("Resolved this run", "resolved_this_run")):
        if key in s:
            lines.append(f"  {label + ':':<30}{s[key]:>8,}")
    if result.top_items:
        lines += ["", "Top items:"]
        for item in result.top_items:
            lines.append(f"  [{item['priority']:>3}] {item['title']} ({item['asset']})")
    if result.regressions:
        lines += ["", f"Regressions: {len(result.regressions)} (high priority)"]
    if result.report_paths:
        lines += ["", "Reports:"] + [f"  {p}" for p in result.report_paths]
    lines += ["", f"Notifications sent: {result.notifications_sent}"]
    return "\n".join(lines)


# --- run (shortcut for `program run`) ------------------------------------------------

def run_run(argv: Sequence[str]) -> int:
    return run_program(["run", *argv])


# --- db maintenance ------------------------------------------------------------------

def run_db(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(prog="shadowscan db", description="Database maintenance.")
    parser.add_argument("action", choices=("stats", "vacuum", "integrity", "backup", "export", "import"))
    parser.add_argument("--database", "-d", type=Path, required=True)
    parser.add_argument("--dest", type=Path, help="destination for backup/export")
    parser.add_argument("--program", default="program", help="program id label for export")
    args = parser.parse_args(argv)
    configure_logging(False)
    if not args.database.exists() and args.action != "import":
        logger.error("database %s not found", args.database)
        return EXIT_FAILURE

    if args.action == "import":
        if not args.dest:
            logger.error("--dest (export file) required for import validation")
            return EXIT_FAILURE
        val = maint.validate_export(args.dest)
        print(f"Export valid={val.ok} version={val.version} program={val.program}")
        for e in val.errors:
            print(f"  ERROR: {e}")
        for t, n in val.table_counts.items():
            print(f"  {t}: {n} rows")
        return EXIT_OK if val.ok else EXIT_FAILURE

    with Database(args.database) as db:
        if args.action == "stats":
            st = maint.stats(db)
            print(f"DB size: {st.size_bytes:,} bytes ({st.page_count} pages x {st.page_size})")
            for name, count in sorted(st.tables.items()):
                print(f"  {name:<28}{count:>10,}")
        elif args.action == "vacuum":
            maint.vacuum(db); print("VACUUM complete.")
        elif args.action == "integrity":
            ok, detail = maint.integrity_check(db)
            print(f"Integrity: {'OK' if ok else 'FAILED'} ({detail})")
            return EXIT_OK if ok else EXIT_FAILURE
        elif args.action == "backup":
            dest = args.dest or args.database.with_suffix(".backup.db")
            maint.backup(db, dest); print(f"Backup written to {dest}")
        elif args.action == "export":
            dest = args.dest or args.database.with_suffix(".export.json")
            maint.export_program(db, args.program, dest); print(f"Exported program intelligence to {dest}")
    return EXIT_OK


# --- feedback / ignore / baseline / note ---------------------------------------------

def run_feedback(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(prog="shadowscan feedback", description="Record researcher feedback (ranking only).")
    parser.add_argument("--database", "-d", type=Path, required=True)
    parser.add_argument("--program", required=True)
    parser.add_argument("--kind", required=True, choices=("category", "endpoint", "finding", "ai"))
    parser.add_argument("--key", required=True)
    parser.add_argument("--verdict", required=True)
    args = parser.parse_args(argv)
    configure_logging(False)
    with Database(args.database) as db:
        store = OpsStore(db); store.ensure_schema(utc_now_iso())
        with db.transaction():
            if args.kind == "ai":
                store.add_ai_feedback(args.program, args.key, None, args.verdict, utc_now_iso())
            else:
                store.add_feedback(args.program, args.kind, args.key, args.verdict, utc_now_iso())
    print(f"Recorded {args.verdict} feedback for {args.kind}:{args.key}")
    return EXIT_OK


def run_ignore(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(prog="shadowscan ignore", description="Manage program ignore rules.")
    parser.add_argument("--database", "-d", type=Path, required=True)
    parser.add_argument("--program", required=True)
    parser.add_argument("--add", nargs=2, metavar=("TYPE", "PATTERN"))
    parser.add_argument("--note", default="")
    parser.add_argument("--list", action="store_true")
    args = parser.parse_args(argv)
    configure_logging(False)
    with Database(args.database) as db:
        store = OpsStore(db); store.ensure_schema(utc_now_iso())
        if args.add:
            with db.transaction():
                rid = store.add_ignore_rule(args.program, args.add[0], args.add[1], args.note, utc_now_iso())
            print(f"Added ignore rule {rid}: {args.add[0]} {args.add[1]}")
        if args.list or not args.add:
            for r in store.ignore_rules(args.program):
                print(f"  [{r['id']}] {r['rule_type']} {r['pattern']}  {r['note'] or ''}")
    return EXIT_OK


def run_baseline(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(prog="shadowscan baseline", description="Manage program baselines.")
    parser.add_argument("--database", "-d", type=Path, required=True)
    parser.add_argument("--program", required=True)
    parser.add_argument("--add", nargs=3, metavar=("KIND", "KEY", "EXPECTATION"))
    parser.add_argument("--note", default="")
    parser.add_argument("--list", action="store_true")
    args = parser.parse_args(argv)
    configure_logging(False)
    with Database(args.database) as db:
        store = OpsStore(db); store.ensure_schema(utc_now_iso())
        if args.add:
            with db.transaction():
                store.add_baseline(args.program, args.add[0], args.add[1], args.add[2], args.note, utc_now_iso())
            print(f"Added baseline: {args.add[0]} {args.add[1]} -> {args.add[2]}")
        if args.list or not args.add:
            for b in store.baselines(args.program):
                print(f"  {b['scope_kind']} {b['scope_key']} -> {b['expectation']}  {b['note'] or ''}")
    return EXIT_OK


def run_schedule(argv: Sequence[str]) -> int:
    from .scheduler import render
    parser = argparse.ArgumentParser(prog="shadowscan schedule", description="Print example scheduler commands.")
    parser.add_argument("program")
    parser.add_argument("--base")
    parser.add_argument("--python", default="python")
    args = parser.parse_args(argv)
    print(render(args.program, python=args.python, base=args.base))
    return EXIT_OK
