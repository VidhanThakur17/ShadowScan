"""Per-program configuration (bug-bounty program profiles) and auth contexts.

A profile is YAML under ``programs/<name>.yaml``. The same ShadowScan install
can safely serve many programs; nothing about program behaviour is hard-coded
globally.

Secrets are never read from the committed YAML. Auth material is referenced
indirectly: a profile names an environment variable (``token_env``) or a local
secrets file path, and the value is resolved at runtime and kept in memory
only. SQLite stores auth-profile *identifiers*, never the secret.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .models import TestingPolicy

try:
    import yaml
except ImportError:  # pragma: no cover - yaml ships with the project
    yaml = None


@dataclass(frozen=True, slots=True)
class AuthProfile:
    """A named authentication context. Holds only *references* to secrets."""

    name: str
    host: str                                 # the single host this material may be sent to
    header_name: str = "Authorization"
    token_env: str | None = None              # environment variable holding the token
    cookie_env: str | None = None             # environment variable holding a cookie string
    description: str = ""

    def resolve_header(self, host: str) -> dict[str, str]:
        """Return the auth header for ``host`` ONLY if it matches this profile's host.

        Cross-host sends are refused: a profile's material is bound to its host.
        """
        if host.lower().rstrip(".") != self.host.lower().rstrip("."):
            return {}
        headers: dict[str, str] = {}
        if self.token_env:
            value = os.environ.get(self.token_env)
            if value:
                headers[self.header_name] = value
        if self.cookie_env:
            cookie = os.environ.get(self.cookie_env)
            if cookie:
                headers["Cookie"] = cookie
        return headers

    @property
    def available(self) -> bool:
        return bool((self.token_env and os.environ.get(self.token_env))
                    or (self.cookie_env and os.environ.get(self.cookie_env)))


@dataclass(slots=True)
class ProgramProfile:
    name: str
    scope_roots: tuple[str, ...] = ()
    excluded_hosts: tuple[str, ...] = ()
    excluded_paths: tuple[str, ...] = ()
    allowed_ports: tuple[int, ...] = ()
    allowed_methods: frozenset[str] = frozenset({"GET", "HEAD", "OPTIONS"})
    global_mode: TestingPolicy = TestingPolicy.SAFE_ACTIVE
    max_requests_per_run: int = 500
    max_requests_per_endpoint: int = 5
    requests_per_second_per_host: float = 2.0
    active_concurrency: int = 4
    introspection_enabled: bool = False
    nuclei_profiles: tuple[str, ...] = ("passive", "exposure", "misconfig")
    researcher_header: tuple[str, str] | None = None
    auth_profiles: dict[str, AuthProfile] = field(default_factory=dict)
    notes: str = ""

    def excluded_path_res(self) -> tuple[re.Pattern[str], ...]:
        return tuple(re.compile(p) for p in self.excluded_paths)


def _coerce_mode(value: Any) -> TestingPolicy:
    try:
        return TestingPolicy(str(value).lower())
    except ValueError:
        return TestingPolicy.SAFE_ACTIVE


def load_profile(path: str | Path) -> ProgramProfile:
    """Load a program profile from YAML. Secrets are referenced, never inlined."""
    if yaml is None:
        raise RuntimeError("PyYAML is required to load program profiles")
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    return profile_from_dict(data)


def profile_from_dict(data: dict[str, Any]) -> ProgramProfile:
    auth: dict[str, AuthProfile] = {}
    for item in data.get("authentication_profiles", []) or []:
        if not isinstance(item, dict) or "name" not in item or "host" not in item:
            continue
        # Reject any attempt to inline a secret in the profile file.
        for forbidden in ("token", "cookie", "secret", "password", "authorization"):
            if forbidden in item:
                raise ValueError(
                    f"auth profile {item.get('name')!r} inlines a secret ({forbidden!r}); "
                    "use token_env/cookie_env to reference an environment variable instead"
                )
        auth[item["name"]] = AuthProfile(
            name=item["name"], host=item["host"],
            header_name=item.get("header_name", "Authorization"),
            token_env=item.get("token_env"), cookie_env=item.get("cookie_env"),
            description=item.get("description", ""),
        )
    rh = data.get("researcher_header")
    researcher_header = None
    if isinstance(rh, dict) and rh.get("name"):
        researcher_header = (str(rh["name"]), str(rh.get("value", "")))
    return ProgramProfile(
        name=str(data.get("name", "unnamed")),
        scope_roots=tuple(data.get("scope_roots", []) or []),
        excluded_hosts=tuple(data.get("excluded_hosts", []) or []),
        excluded_paths=tuple(data.get("excluded_paths", []) or []),
        allowed_ports=tuple(int(p) for p in (data.get("allowed_ports", []) or [])),
        allowed_methods=frozenset(m.upper() for m in (data.get("allowed_methods", ["GET", "HEAD", "OPTIONS"]))),
        global_mode=_coerce_mode(data.get("global_mode", "safe_active")),
        max_requests_per_run=int(data.get("max_requests_per_run", 500)),
        max_requests_per_endpoint=int(data.get("max_requests_per_endpoint", 5)),
        requests_per_second_per_host=float(data.get("requests_per_second_per_host", 2.0)),
        active_concurrency=int(data.get("active_concurrency", 4)),
        introspection_enabled=bool(data.get("graphql_introspection", False)),
        nuclei_profiles=tuple(data.get("nuclei_profiles", ["passive", "exposure", "misconfig"])),
        researcher_header=researcher_header,
        auth_profiles=auth,
        notes=str(data.get("notes", "")),
    )


def default_profile(name: str = "default") -> ProgramProfile:
    return ProgramProfile(name=name)
