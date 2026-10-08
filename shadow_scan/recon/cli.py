"""CLI implementations for the recon, review and stats subcommands."""

from __future__ import annotations

import argparse
import asyncio
import logging
from collections.abc import Sequence
from pathlib import Path

from ..config import ScanConfig
from ..database import Database
from ..utils import configure_logging
from .crawler import CrawlConfig
from .pipeline import PORT_PROFILES, ReconComponents, ReconConfig, ReconPipeline
from .recon_db import ReconStore
from .review import VALID_STATUSES, set_status, show_queue
from .scope import ScopeEngine

logger = logging.getLogger("shadow_scan.recon")

EXIT_OK, EXIT_FAILURE, EXIT_INTERRUPTED = 0, 1, 130


def _load_scope(path: Path, probe_unknown: bool) -> ScopeEngine:
    with path.open("r", encoding="utf-8-sig", errors="replace") as handle:
        return ScopeEngine.parse(handle.readlines(), probe_unknown=probe_unknown)


def run_recon(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(prog="shadow_scan recon",
                                     description="Attack-surface recon over an authorized scope. Bounded and passive.")
    parser.add_argument("--input", "-i", type=Path, required=True, help="scope file (hosts, wildcards, URLs, exclusions)")
    parser.add_argument("--database", "-d", type=Path, default=Path("shadowscan.db"), help="SQLite database")
    parser.add_argument("--hostnames", type=Path, help="optional plain hostname file to import as discovery input")
    parser.add_argument("--concurrency", "-c", type=int, default=50, help="HTTP concurrency")
    parser.add_argument("--timeout", "-t", type=float, default=10.0, help="per-request timeout seconds")
    parser.add_argument("--ports", default="fast", help="port profile: fast | web_extended | custom")
    parser.add_argument("--custom-ports", help="comma-separated ports when --ports custom")
    parser.add_argument("--max-depth", type=int, default=2, help="crawl depth")
    parser.add_argument("--max-urls", type=int, default=1000, help="total crawl URL cap")
    parser.add_argument("--probe-unknown", action="store_true", help="also actively probe UNKNOWN-scope hosts")
    parser.add_argument("--resume", action="store_true", help="resume the last unfinished recon run")
    parser.add_argument("--insecure", action="store_true", help="skip TLS verification")
    parser.add_argument("--no-external-tools", action="store_true",
                        help="do not run external binaries (subfinder/gau/naabu/...); crawl-only recon")
    parser.add_argument("--no-services", action="store_true", help="skip port discovery")
    parser.add_argument("--no-urls", action="store_true", help="skip passive URL collection tools")
    parser.add_argument("--no-crawl", action="store_true", help="skip crawling")
    parser.add_argument("--no-javascript", action="store_true", help="skip JavaScript analysis")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args(argv)
    configure_logging(args.verbose)

    try:
        scope = _load_scope(args.input, args.probe_unknown)
    except OSError as exc:
        logger.error("Cannot read scope file %s: %s", args.input, exc)
        return EXIT_FAILURE
    if not scope.in_scope_hosts:
        logger.warning("Scope has no exact in-scope hosts; discovery/crawl may find nothing")

    seed_hosts: tuple[str, ...] = ()
    if args.hostnames:
        try:
            seed_hosts = tuple(h.strip() for h in args.hostnames.read_text(encoding="utf-8-sig").splitlines() if h.strip())
        except OSError as exc:
            logger.error("Cannot read hostname file %s: %s", args.hostnames, exc)
            return EXIT_FAILURE

    if args.ports == "custom" and not args.custom_ports:
        logger.error("--ports custom requires --custom-ports")
        return EXIT_FAILURE
    if args.ports not in (*PORT_PROFILES, "custom"):
        logger.error("Unknown port profile %r (choose: %s, custom)", args.ports, ", ".join(PORT_PROFILES))
        return EXIT_FAILURE

    scan_config = ScanConfig(
        database_path=args.database, concurrency=args.concurrency, request_timeout=args.timeout,
        total_timeout=max(3 * args.timeout, 30.0), verify_tls=not args.insecure,
    )
    config = ReconConfig(
        scope=scope, scan_config=scan_config,
        crawl=CrawlConfig(max_depth=args.max_depth, max_total_urls=args.max_urls),
        seed_hosts=seed_hosts, root_domains=tuple(sorted(scope.in_scope_hosts)),
        port_profile=args.ports, custom_ports=args.custom_ports,
        enable_services=not args.no_services, enable_urls=not args.no_urls,
        enable_crawl=not args.no_crawl, enable_javascript=not args.no_javascript,
    )
    pipeline = ReconPipeline(config, ReconComponents(use_real_tools=not args.no_external_tools))
    try:
        run_id = asyncio.run(pipeline.run(resume=args.resume))
    except KeyboardInterrupt:
        logger.warning("Recon interrupted; progress is saved and can be resumed with --resume")
        return EXIT_INTERRUPTED

    print(show_queue(str(args.database), statuses=["new", "reviewing", "interesting"], limit=20), flush=True)
    logger.info("Recon run #%s complete. Review with: shadow_scan review --database %s", run_id, args.database)
    return EXIT_OK


def run_review(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(prog="shadow_scan review", description="Inspect and triage the recon review queue.")
    parser.add_argument("--database", "-d", type=Path, default=Path("shadowscan.db"))
    parser.add_argument("--status", action="append", choices=VALID_STATUSES,
                        help="filter by status (repeatable); default shows active items")
    parser.add_argument("--limit", type=int, default=50)
    parser.add_argument("--all", action="store_true", help="include dismissed/resolved items")
    parser.add_argument("--set", nargs=2, metavar=("ASSET", "STATUS"), help="set an asset's review status")
    parser.add_argument("--summary", action="store_true", help="one line per item")
    args = parser.parse_args(argv)
    configure_logging(False)

    if not Path(args.database).exists():
        logger.error("Database %s not found; run 'shadow_scan recon' first", args.database)
        return EXIT_FAILURE

    if args.set:
        asset, status = args.set
        try:
            changed = set_status(str(args.database), asset, status)
        except ValueError as exc:
            logger.error("%s", exc)
            return EXIT_FAILURE
        print(f"{asset}: status set to {status}" if changed else f"{asset}: not found in review queue")
        return EXIT_OK

    statuses = args.status or (None if args.all else ["new", "reviewing", "interesting"])
    print(show_queue(str(args.database), statuses=statuses, limit=args.limit, detail=not args.summary), flush=True)
    return EXIT_OK


_STATS_TABLES = [
    ("hosts", "hosts"), ("resolving hosts", "dns_records WHERE status='resolves'"),
    ("open services", "services WHERE status='open'"), ("urls", "urls"),
    ("javascript assets", "javascript_assets"), ("js findings", "js_findings"),
    ("endpoints", "endpoints"), ("parameters", "parameters"),
    ("technologies", "technologies"), ("recon signals", "recon_signals"),
    ("review items", "review_items"),
]


def run_stats(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(prog="shadow_scan stats", description="Summarize the recon datastore.")
    parser.add_argument("--database", "-d", type=Path, default=Path("shadowscan.db"))
    args = parser.parse_args(argv)
    configure_logging(False)

    if not Path(args.database).exists():
        logger.error("Database %s not found", args.database)
        return EXIT_FAILURE

    db = Database(args.database)
    db.open()
    try:
        store = ReconStore(db)
        store.ensure_schema()
        lines = ["ShadowScan recon stats", ""]
        for label, table in _STATS_TABLES:
            try:
                count = db.conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            except Exception:
                count = 0
            lines.append(f"{label + ':':<22}{count:>8,}")
        review_rows = db.conn.execute(
            "SELECT status, COUNT(*) FROM review_items GROUP BY status ORDER BY status"
        ).fetchall()
        if review_rows:
            lines += ["", "Review items by status:"]
            lines += [f"  {r[0]:<14}{r[1]:>6,}" for r in review_rows]
        runs = db.conn.execute("SELECT COUNT(*), SUM(status='completed') FROM recon_runs").fetchone()
        lines += ["", f"Recon runs: {runs[0] or 0} ({runs[1] or 0} completed)"]
    finally:
        db.close()
    print("\n".join(lines), flush=True)
    return EXIT_OK
