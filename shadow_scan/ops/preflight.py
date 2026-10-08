"""Preflight checks and external-tool health. No target interaction here."""

from __future__ import annotations

import shutil
import sqlite3
import sys
from dataclasses import dataclass, field
from pathlib import Path

from ..database import Database

_OPTIONAL_TOOLS = ("subfinder", "amass", "findomain", "gau", "waybackurls", "naabu", "nmap", "nuclei")
_REQUIRED_PY = (3, 12)


@dataclass(frozen=True, slots=True)
class CheckResult:
    name: str
    ok: bool
    detail: str
    required: bool = False


@dataclass(slots=True)
class PreflightReport:
    results: list[CheckResult] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return all(r.ok for r in self.results if r.required)

    @property
    def degraded(self) -> list[str]:
        return [r.name for r in self.results if not r.ok and not r.required]

    def add(self, name: str, ok: bool, detail: str, required: bool = False) -> None:
        self.results.append(CheckResult(name, ok, detail, required))


def _tool_version(binary: str) -> str | None:
    import subprocess
    for flag in ("-version", "--version", "version", "-V"):
        try:
            proc = subprocess.run([binary, flag], capture_output=True, text=True, timeout=10,
                                  shell=False, check=False, encoding="utf-8", errors="replace")
        except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
            continue
        out = (proc.stdout or proc.stderr).strip()
        if out:
            return out.splitlines()[0][:80]
    return "installed"


def preflight(db_path: Path, *, program_config_ok: bool = True, ai_enabled: bool = False,
              output_dirs: list[Path] | None = None, store=None, now: str = "") -> PreflightReport:
    """Run all preflight checks. Optional-tool failures are degraded, not fatal."""
    report = PreflightReport()

    # Python version (required).
    report.add("python", sys.version_info[:2] >= _REQUIRED_PY,
               f"{sys.version_info.major}.{sys.version_info.minor} (need >= {_REQUIRED_PY[0]}.{_REQUIRED_PY[1]})",
               required=True)

    # Database accessibility (required).
    try:
        with sqlite3.connect(str(db_path)) as c:
            c.execute("PRAGMA user_version")
        report.add("database", True, f"accessible at {db_path}", required=True)
    except sqlite3.Error as exc:
        report.add("database", False, f"inaccessible: {exc}", required=True)

    # Program config (required).
    report.add("program_config", program_config_ok,
               "valid" if program_config_ok else "invalid or missing", required=True)

    # Parser dependencies (tree-sitter for AST; optional — falls back).
    try:
        import tree_sitter_javascript  # noqa: F401
        from tree_sitter import Language  # noqa: F401
        report.add("ast_parser", True, "tree-sitter JavaScript available")
    except Exception:
        report.add("ast_parser", False, "tree-sitter unavailable (AST falls back to lightweight extractor)")

    # yaml (required for program workspaces).
    try:
        import yaml  # noqa: F401
        report.add("yaml", True, "PyYAML available", required=True)
    except ImportError:
        report.add("yaml", False, "PyYAML missing", required=True)

    # External tools (optional). Record health when a store is provided.
    for tool in _OPTIONAL_TOOLS:
        present = shutil.which(tool) is not None
        version = _tool_version(tool) if present else None
        report.add(f"tool:{tool}", present, version or "not installed")
        if store is not None:
            store.record_tool_health(tool, version, present, now)

    # AI provider configuration (optional).
    if ai_enabled:
        import os
        has_key = bool(os.environ.get("OPENAI_API_KEY") or os.environ.get("ANTHROPIC_API_KEY")
                       or os.environ.get("SHADOWSCAN_AI_PROVIDER") == "mock")
        report.add("ai_provider", has_key, "configured" if has_key else "enabled but no API key/provider set")

    # Output directories writable (required).
    for d in (output_dirs or []):
        try:
            d.mkdir(parents=True, exist_ok=True)
            probe = d / ".write_test"
            probe.write_text("ok", encoding="utf-8")
            probe.unlink()
            report.add(f"writable:{d.name}", True, str(d), required=True)
        except OSError as exc:
            report.add(f"writable:{d.name}", False, f"{d}: {exc}", required=True)

    return report
