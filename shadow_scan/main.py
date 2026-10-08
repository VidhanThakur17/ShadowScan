"""Command-line entry point: ``python -m shadow_scan.main --input domains.txt``."""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from collections.abc import Sequence
from pathlib import Path

from . import config as defaults
from .config import ScanConfig
from .delta import build_report, sort_changes, write_report
from .models import RunStatus, RunSummary
from .scanner import Scanner
from .utils import configure_logging, load_targets

logger = logging.getLogger("shadow_scan")

EXIT_OK = 0
EXIT_FAILURE = 1
EXIT_INTERRUPTED = 130


def _header(value: str) -> tuple[str, str]:
    name, sep, content = value.partition(":")
    if not sep or not name.strip():
        raise argparse.ArgumentTypeError(f"expected 'Name: value', got {value!r}")
    return name.strip(), content.strip()


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python -m shadow_scan.main",
        description="ShadowScan HTTP asset monitoring and change detection. Authorized targets only.",
    )
    parser.add_argument("--input", "-i", type=Path, default=Path("domains.txt"), help="targets file (default: %(default)s)")
    parser.add_argument("--database", "-d", type=Path, default=Path("shadowscan.db"), help="SQLite database (default: %(default)s)")
    parser.add_argument("--output", "-o", type=Path, default=Path("deltas.json"), help="delta report (default: %(default)s)")
    parser.add_argument("--concurrency", "-c", type=int, default=defaults.MAX_CONCURRENCY, help="max in-flight targets (default: %(default)s)")
    parser.add_argument("--timeout", "-t", type=float, default=defaults.REQUEST_TIMEOUT, help="connect/read timeout in seconds (default: %(default)s)")
    parser.add_argument("--total-timeout", type=float, default=None, help="hard per-request ceiling in seconds (default: max(3 x timeout, 30))")
    parser.add_argument("--max-bytes", type=int, default=defaults.MAX_RESPONSE_BYTES, help="max body bytes read per response (default: %(default)s)")
    parser.add_argument("--max-redirects", type=int, default=defaults.MAX_REDIRECTS, help="max in-scope redirects followed (default: %(default)s)")
    parser.add_argument("--no-http-fallback", action="store_true", help="do not retry scheme-less targets over HTTP")
    parser.add_argument("--allow-subdomain-redirects", action="store_true", help="also follow redirects to subdomains of supplied hosts")
    parser.add_argument("--insecure", action="store_true", help="skip TLS certificate verification")
    parser.add_argument("--user-agent", default=defaults.DEFAULT_USER_AGENT, help="User-Agent header")
    parser.add_argument("--header", "-H", type=_header, action="append", default=[], metavar="'NAME: VALUE'", help="extra request header (repeatable)")
    parser.add_argument("--verbose", "-v", action="store_true", help="debug logging")
    return parser.parse_args(argv)


def build_config(args: argparse.Namespace) -> ScanConfig:
    total_timeout = args.total_timeout if args.total_timeout is not None else max(3 * args.timeout, defaults.TOTAL_REQUEST_TIMEOUT)
    return ScanConfig(
        input_path=args.input,
        database_path=args.database,
        output_path=args.output,
        concurrency=args.concurrency,
        request_timeout=args.timeout,
        total_timeout=total_timeout,
        max_response_bytes=args.max_bytes,
        max_redirects=args.max_redirects,
        http_fallback=not args.no_http_fallback,
        verify_tls=not args.insecure,
        allow_subdomain_redirects=args.allow_subdomain_redirects,
        user_agent=args.user_agent,
        extra_headers=tuple(args.header),
    )


def format_summary(summary: RunSummary, top_n: int, show_all: bool = False) -> str:
    """Concise end-of-run console summary. ``show_all`` lists every change (verbose mode)."""
    interesting = sum(1 for c in summary.changes if c.interesting)
    rows = [
        ("Targets", summary.targets_total),
        ("Reachable", summary.reachable),
        ("Unreachable", summary.unreachable),
        ("Incomplete", summary.incomplete),
        ("Changes", len(summary.changes)),
        ("Interesting", interesting),
        ("Noise suppressed", summary.raw_only_changes),
    ]
    lines = [f"ShadowScan {summary.status.value}", ""]
    lines += [f"{label + ':':<18}{value:>8,}" for label, value in rows]
    changes = sort_changes(summary.changes)
    shown = changes if show_all else changes[:top_n]
    if shown:
        width = min(max(len(c.target) for c in shown), 48)
        lines += ["", "All changes:" if show_all else "Top changes:", ""]
        for change in shown:
            marker = "*" if change.interesting else " "
            lines.append(f"[{change.review_priority:>3}]{marker} {change.target:<{width}}  {change.describe()}")
        if len(changes) > len(shown):
            lines.append(f"... {len(changes) - len(shown)} more in the delta report (--verbose lists all)")
        if interesting:
            lines += ["", "* interesting: the transition may deserve human review (not a vulnerability finding)"]
    return "\n".join(lines)


def run_monitor(argv: Sequence[str] | None = None) -> int:
    """The HTTP monitoring command (also the legacy top-level invocation)."""
    args = parse_args(argv)
    configure_logging(args.verbose)

    try:
        config = build_config(args)
        config.validate()
    except ValueError as exc:
        logger.error("Invalid configuration: %s", exc)
        return EXIT_FAILURE

    try:
        targets, stats = load_targets(config.input_path)
    except OSError as exc:
        logger.error("Cannot read targets file %s: %s", config.input_path, exc)
        return EXIT_FAILURE

    logger.info(
        "Loaded %s unique targets (%s duplicates, %s invalid)",
        f"{stats.unique:,}", f"{stats.duplicates:,}", f"{stats.invalid:,}",
    )
    if not targets:
        logger.warning("No valid targets in %s; nothing to do", config.input_path)

    try:
        summary = asyncio.run(Scanner(config, targets).run())
    except KeyboardInterrupt:
        # Second Ctrl+C during shutdown: committed batches are safe thanks to WAL.
        logger.warning("Forced exit; %s was not written", config.output_path)
        return EXIT_INTERRUPTED

    print(format_summary(summary, config.top_changes_shown, show_all=args.verbose), flush=True)

    try:
        write_report(config.output_path, build_report(summary))
        logger.info("Wrote %d changes to %s", len(summary.changes), config.output_path)
    except OSError as exc:
        logger.error("Cannot write %s: %s", config.output_path, exc)
        return EXIT_FAILURE

    if summary.status is RunStatus.INTERRUPTED:
        return EXIT_INTERRUPTED
    return EXIT_OK if summary.status is RunStatus.COMPLETED else EXIT_FAILURE


# --- recon / review / stats subcommands ------------------------------------------------

_SUBCOMMANDS = ("monitor", "recon", "review", "stats")


def run_recon(argv: Sequence[str]) -> int:
    """Run the recon & attack-surface pipeline. Imports are local so the monitor
    path has no recon import cost."""
    from .recon.cli import run_recon as _run_recon
    return _run_recon(argv)


def run_review(argv: Sequence[str]) -> int:
    from .recon.cli import run_review as _run_review
    return _run_review(argv)


def run_stats(argv: Sequence[str]) -> int:
    from .recon.cli import run_stats as _run_stats
    return _run_stats(argv)


def main(argv: Sequence[str] | None = None) -> int:
    """Dispatch to a subcommand. A bare invocation (no subcommand) runs monitor,
    preserving the Phase-1/2 ``--input domains.txt`` form."""
    args = list(sys.argv[1:] if argv is None else argv)
    if args and args[0] in _SUBCOMMANDS:
        command, rest = args[0], args[1:]
    else:
        command, rest = "monitor", args          # backward-compatible default
    dispatch = {
        "monitor": run_monitor, "recon": run_recon, "review": run_review, "stats": run_stats,
    }
    return dispatch[command](rest)


if __name__ == "__main__":
    sys.exit(main())
