"""Program workspace model and configuration precedence.

Layout (config is committed; runtime is git-ignored)::

    programs/<id>/program.yaml   scope.yaml   ignore.yaml   auth.example.yaml
    runtime/<id>/   shadowscan.db   logs/   exports/   reports/

Configuration precedence (least to most specific)::

    built-in defaults  <  global config  <  program config  <  env vars  <  CLI overrides

Security policy is combined safety-first: a more restrictive ``global_mode``
always wins; it can only be loosened by an explicit, unambiguous program/CLI
setting. Secrets never live in committed files — auth is referenced by env-var
name and resolved at runtime.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from ..secanalysis.models import TestingPolicy, most_restrictive
from ..secanalysis.profiles import ProgramProfile, profile_from_dict

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

_POLICY_RANK = {TestingPolicy.DISALLOWED: 0, TestingPolicy.REVIEW_REQUIRED: 1,
                TestingPolicy.PASSIVE_ONLY: 2, TestingPolicy.SAFE_ACTIVE: 3}

DEFAULT_STAGES = ("preflight", "discovery", "dns", "monitor", "services", "urls",
                  "crawl", "javascript", "enrichment", "correlation",
                  "security_analysis", "validation", "ai_analysis", "review", "reporting", "notifications")


@dataclass(slots=True)
class ProgramConfig:
    program_id: str
    name: str = ""
    platform: str = "generic"
    scope_roots: tuple[str, ...] = ()
    excluded_hosts: tuple[str, ...] = ()
    enabled_stages: tuple[str, ...] = DEFAULT_STAGES
    report_formats: tuple[str, ...] = ("json", "markdown")
    report_formatter: str = "generic"           # generic | hackerone | bugcrowd
    notify_min_priority: int = 80
    notify_categories: tuple[str, ...] = ()
    notify_providers: tuple[str, ...] = ("console",)
    profile: ProgramProfile = field(default_factory=lambda: ProgramProfile(name="default"))
    researcher_notes: str = ""
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class Workspace:
    program_id: str
    config_dir: Path
    runtime_dir: Path

    @property
    def db_path(self) -> Path:
        return self.runtime_dir / "shadowscan.db"

    @property
    def logs_dir(self) -> Path:
        return self.runtime_dir / "logs"

    @property
    def exports_dir(self) -> Path:
        return self.runtime_dir / "exports"

    @property
    def reports_dir(self) -> Path:
        return self.runtime_dir / "reports"

    @property
    def lock_path(self) -> Path:
        return self.runtime_dir / "run.lock"

    def ensure_runtime(self) -> None:
        for d in (self.runtime_dir, self.logs_dir, self.exports_dir, self.reports_dir):
            d.mkdir(parents=True, exist_ok=True)


class WorkspaceManager:
    """Resolves program workspaces under a base directory (default: the CWD)."""

    def __init__(self, base: Path | str = ".", *, global_config: dict[str, Any] | None = None) -> None:
        self._base = Path(base)
        self._global = global_config or {}

    @property
    def programs_dir(self) -> Path:
        return self._base / "programs"

    @property
    def runtime_root(self) -> Path:
        return self._base / "runtime"

    def list_programs(self) -> list[str]:
        if not self.programs_dir.exists():
            return []
        return sorted(p.name for p in self.programs_dir.iterdir()
                      if p.is_dir() and (p / "program.yaml").exists())

    def workspace(self, program_id: str) -> Workspace:
        return Workspace(program_id, self.programs_dir / program_id, self.runtime_root / program_id)

    def exists(self, program_id: str) -> bool:
        return (self.programs_dir / program_id / "program.yaml").exists()

    def create(self, program_id: str, *, name: str | None = None, platform: str = "generic") -> Workspace:
        ws = self.workspace(program_id)
        ws.config_dir.mkdir(parents=True, exist_ok=True)
        ws.ensure_runtime()
        if yaml is None:
            raise RuntimeError("PyYAML is required to scaffold a program")
        (ws.config_dir / "program.yaml").write_text(_scaffold_program(program_id, name or program_id, platform),
                                                     encoding="utf-8")
        (ws.config_dir / "scope.yaml").write_text(_SCAFFOLD_SCOPE, encoding="utf-8")
        (ws.config_dir / "ignore.yaml").write_text(_SCAFFOLD_IGNORE, encoding="utf-8")
        (ws.config_dir / "auth.example.yaml").write_text(_SCAFFOLD_AUTH, encoding="utf-8")
        return ws

    def load(self, program_id: str, *, cli_overrides: dict[str, Any] | None = None) -> ProgramConfig:
        """Load a program's merged configuration, honoring precedence."""
        if yaml is None:
            raise RuntimeError("PyYAML is required to load program configuration")
        ws = self.workspace(program_id)
        if not self.exists(program_id):
            raise FileNotFoundError(f"program {program_id!r} not found under {self.programs_dir}")
        program_raw = _read_yaml(ws.config_dir / "program.yaml")
        scope_raw = _read_yaml(ws.config_dir / "scope.yaml")
        # auth.yaml is optional and git-ignored; auth.example.yaml is the template.
        auth_raw = _read_yaml(ws.config_dir / "auth.yaml") if (ws.config_dir / "auth.yaml").exists() else {}

        # defaults < global < program  (dict merge, program wins)
        merged: dict[str, Any] = {}
        merged.update(self._global)
        merged.update(program_raw)
        if scope_raw.get("scope_roots"):
            merged["scope_roots"] = scope_raw["scope_roots"]
        if scope_raw.get("excluded_hosts"):
            merged["excluded_hosts"] = scope_raw["excluded_hosts"]
        if auth_raw.get("authentication_profiles"):
            merged["authentication_profiles"] = auth_raw["authentication_profiles"]

        # env overrides for a small set of operational keys
        env_mode = os.environ.get("SHADOWSCAN_GLOBAL_MODE")
        if env_mode:
            merged["global_mode"] = env_mode

        # CLI overrides win last.
        if cli_overrides:
            merged.update({k: v for k, v in cli_overrides.items() if v is not None})

        profile = profile_from_dict(merged)
        config = ProgramConfig(
            program_id=program_id,
            name=str(merged.get("name", program_id)),
            platform=str(merged.get("platform", "generic")),
            scope_roots=tuple(merged.get("scope_roots", []) or []),
            excluded_hosts=tuple(merged.get("excluded_hosts", []) or []),
            enabled_stages=tuple(merged.get("enabled_stages", DEFAULT_STAGES) or DEFAULT_STAGES),
            report_formats=tuple(merged.get("report_formats", ["json", "markdown"])),
            report_formatter=str(merged.get("report_formatter", "generic")),
            notify_min_priority=int(merged.get("notify_min_priority", 80)),
            notify_categories=tuple(merged.get("notify_categories", []) or []),
            notify_providers=tuple(merged.get("notify_providers", ["console"])),
            profile=profile,
            researcher_notes=str(merged.get("researcher_notes", "")),
            raw=merged,
        )
        # Safety-first: a more restrictive mode from env/global can only tighten.
        base_mode = profile.global_mode
        if env_mode:
            config.profile.global_mode = most_restrictive(base_mode, _coerce(env_mode))
        return config


def combine_policy_modes(*modes: TestingPolicy) -> TestingPolicy:
    """More restrictive security policy wins (used when merging config sources)."""
    return most_restrictive(*modes)


def _coerce(value: str) -> TestingPolicy:
    try:
        return TestingPolicy(value.lower())
    except ValueError:
        return TestingPolicy.SAFE_ACTIVE


def _read_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


# --- validation -----------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class ValidationIssue:
    severity: str   # "error" | "warning"
    message: str


def validate_config(config: ProgramConfig) -> list[ValidationIssue]:
    """Catch unsafe/invalid configuration before any recon begins."""
    issues: list[ValidationIssue] = []
    if not config.scope_roots:
        issues.append(ValidationIssue("error", "scope has no roots; nothing is in scope"))
    for root in config.scope_roots:
        if root.startswith("*") and not root.startswith("*."):
            issues.append(ValidationIssue("error", f"invalid wildcard scope entry {root!r} (use *.domain)"))
    # Overlapping exclusion: an excluded host that is also an exact scope root.
    exact = {r for r in config.scope_roots if not r.startswith(("*.", "@", "!", "http"))}
    for ex in config.excluded_hosts:
        if ex in exact:
            issues.append(ValidationIssue("error", f"host {ex!r} is both in scope and excluded"))
    prof = config.profile
    if prof.requests_per_second_per_host <= 0 or prof.requests_per_second_per_host > 50:
        issues.append(ValidationIssue("warning", f"unusual rate limit {prof.requests_per_second_per_host}/s per host"))
    if prof.max_requests_per_run > 100_000:
        issues.append(ValidationIssue("warning", "max_requests_per_run is very large"))
    if prof.active_concurrency > 50:
        issues.append(ValidationIssue("warning", "active_concurrency is very high"))
    disallowed = {"get", "head", "options"}
    for method in prof.allowed_methods:
        if method.lower() not in disallowed:
            issues.append(ValidationIssue("warning",
                          f"allowed_methods includes {method!r}; state-changing methods are never auto-invoked"))
    # Auth host binding + missing secret references.
    for name, auth in prof.auth_profiles.items():
        if not auth.host:
            issues.append(ValidationIssue("error", f"auth profile {name!r} has no host binding"))
        if not (auth.token_env or auth.cookie_env):
            issues.append(ValidationIssue("error", f"auth profile {name!r} references no secret (token_env/cookie_env)"))
        elif not auth.available:
            issues.append(ValidationIssue("warning",
                          f"auth profile {name!r} secret env var is not set in this environment"))
    for profile_name in prof.nuclei_profiles:
        if profile_name not in ("passive", "exposure", "misconfig", "safe_web"):
            issues.append(ValidationIssue("warning", f"unknown/unsafe nuclei profile {profile_name!r}"))
    for stage in config.enabled_stages:
        if stage not in DEFAULT_STAGES:
            issues.append(ValidationIssue("warning", f"unknown stage {stage!r} in enabled_stages"))
    return issues


# --- scaffolding ----------------------------------------------------------------------

def _scaffold_program(pid: str, name: str, platform: str) -> str:
    return f"""# ShadowScan program: {pid}
name: {name}
platform: {platform}            # hackerone | bugcrowd | generic

global_mode: safe_active        # passive_only | safe_active (more restrictive always wins)
allowed_methods: [GET, HEAD, OPTIONS]

max_requests_per_run: 500
max_requests_per_endpoint: 5
requests_per_second_per_host: 2.0
active_concurrency: 4

graphql_introspection: false
nuclei_profiles: [passive, exposure, misconfig]

enabled_stages: [preflight, discovery, dns, monitor, services, urls, crawl, javascript,
                 enrichment, correlation, security_analysis, validation, ai_analysis,
                 review, reporting, notifications]

report_formats: [json, markdown]
report_formatter: {platform}

notify_min_priority: 80
notify_categories: [authorization, exposure, subdomain_takeover]
notify_providers: [console, file]

# researcher_header: {{ name: X-Bug-Bounty, value: shadowscan-researcher }}
researcher_notes: ""
"""


_SCAFFOLD_SCOPE = """# Scope roots (ScopeEngine syntax). Keep secrets out of this file.
scope_roots:
  - example.com
  - "*.example.com"
  - "@scheme https"
excluded_hosts:
  - admin.internal.example.com
"""

_SCAFFOLD_IGNORE = """# Program-scoped ignore/baseline seeds (optional). These are also managed via the CLI.
ignore_rules: []     # e.g. [{type: content_change, pattern: "www.example.com/news"}]
baselines: []        # e.g. [{scope: endpoint, key: "api.example.com/status", expectation: "403 expected"}]
"""

_SCAFFOLD_AUTH = """# Copy to auth.yaml (git-ignored) and reference env vars. NEVER inline secrets here.
authentication_profiles:
  - name: viewer
    host: api.example.com
    header_name: Authorization
    token_env: SHADOWSCAN_PROGRAM_X_VIEWER_TOKEN
  - name: admin
    host: api.example.com
    header_name: Authorization
    token_env: SHADOWSCAN_PROGRAM_X_ADMIN_TOKEN
"""
