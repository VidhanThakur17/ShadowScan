"""First-class scope engine.

Every discovered hostname, URL, redirect, endpoint and service passes through
:class:`ScopeEngine` before any active interaction. The engine is deterministic
and host-based, extending the monitoring :class:`~shadow_scan.utils.ScopePolicy`
idea with wildcard roots, explicit URLs, allowed schemes/ports and exclusions.

A scope file looks like::

    # comments allowed
    example.com                 # exact host
    *.example.com               # wildcard root (subdomains, not the apex)
    api.example.com
    https://portal.example.com  # explicit URL -> host + scheme + port constraint
    !excluded.example.com       # excluded host
    !~\\.internal\\.example\\.com$   # excluded regex pattern (prefix: !~)
    @ports 80,443,8443          # directive: allowed ports (applies to URL/service checks)
    @scheme https               # directive: restrict allowed schemes

Classification is one of IN_SCOPE / OUT_OF_SCOPE / UNKNOWN:

* a host matching an exclusion is OUT_OF_SCOPE;
* a host matching an exact entry or a wildcard root is IN_SCOPE;
* anything else is UNKNOWN (stored for review, never actively probed unless the
  caller explicitly opts in via ``probe_unknown``).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from ..utils import InvalidTargetError, normalize_target
from .models import ScopeClass

_DEFAULT_PORTS = {"http": 80, "https": 443}


@dataclass(slots=True)
class ScopeRules:
    exact_hosts: set[str] = field(default_factory=set)
    wildcard_roots: set[str] = field(default_factory=set)   # "example.com" means *.example.com
    excluded_hosts: set[str] = field(default_factory=set)
    excluded_patterns: list[re.Pattern[str]] = field(default_factory=list)
    allowed_schemes: set[str] = field(default_factory=lambda: {"http", "https"})
    allowed_ports: set[int] | None = None                   # None = any port allowed
    # Hosts with an explicit scheme/port constraint from an explicit URL entry.
    url_constraints: dict[str, set[int]] = field(default_factory=dict)


class ScopeEngine:
    """Validates and classifies discovered objects against scope rules."""

    def __init__(self, rules: ScopeRules, *, probe_unknown: bool = False) -> None:
        self._rules = rules
        self._probe_unknown = probe_unknown

    # -- construction ----------------------------------------------------------------

    @classmethod
    def parse(cls, lines: list[str], *, probe_unknown: bool = False) -> ScopeEngine:
        rules = ScopeRules()
        for raw in lines:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("@"):
                cls._apply_directive(rules, line)
                continue
            if line.startswith("!~"):
                try:
                    rules.excluded_patterns.append(re.compile(line[2:].strip()))
                except re.error:
                    continue
                continue
            if line.startswith("!"):
                host = cls._host_of(line[1:].strip())
                if host:
                    rules.excluded_hosts.add(host)
                continue
            cls._add_entry(rules, line)
        return cls(rules, probe_unknown=probe_unknown)

    @staticmethod
    def _apply_directive(rules: ScopeRules, line: str) -> None:
        name, _, value = line[1:].partition(" ")
        value = value.strip()
        if name == "ports":
            ports = {int(p) for p in re.split(r"[,\s]+", value) if p.isdigit()}
            rules.allowed_ports = (rules.allowed_ports or set()) | ports
        elif name == "scheme":
            schemes = {s.lower() for s in re.split(r"[,\s]+", value) if s}
            if schemes:
                rules.allowed_schemes = schemes

    @classmethod
    def _add_entry(cls, rules: ScopeRules, line: str) -> None:
        if line.startswith("*."):
            root = cls._host_of(line[2:])
            if root:
                rules.wildcard_roots.add(root)
            return
        if "://" in line:
            parts = urlsplit(line)
            host = cls._host_of(parts.hostname or "")
            if not host:
                return
            rules.exact_hosts.add(host)
            if parts.scheme:
                rules.allowed_schemes = rules.allowed_schemes & {parts.scheme.lower()} or {parts.scheme.lower()}
            port = parts.port or _DEFAULT_PORTS.get((parts.scheme or "").lower())
            if port is not None:
                rules.url_constraints.setdefault(host, set()).add(port)
            return
        host = cls._host_of(line)
        if host:
            rules.exact_hosts.add(host)

    @staticmethod
    def _host_of(raw: str) -> str | None:
        raw = raw.strip()
        if not raw:
            return None
        try:
            if "://" in raw:
                return urlsplit(raw).hostname
            return normalize_target(raw).hostname
        except InvalidTargetError:
            # Fall back to a lenient lower-cased host so odd scope entries still load.
            host = raw.split("/")[0].split(":")[0].strip().lower().rstrip(".")
            return host or None

    # -- classification --------------------------------------------------------------

    def classify_host(self, hostname: str | None) -> ScopeClass:
        if not hostname:
            return ScopeClass.OUT_OF_SCOPE
        host = hostname.lower().rstrip(".")
        if host in self._rules.excluded_hosts or any(p.search(host) for p in self._rules.excluded_patterns):
            return ScopeClass.OUT_OF_SCOPE
        if host in self._rules.exact_hosts or self._matches_wildcard(host):
            return ScopeClass.IN_SCOPE
        return ScopeClass.UNKNOWN

    def _matches_wildcard(self, host: str) -> bool:
        labels = host.split(".")
        # *.example.com matches sub.example.com but not example.com itself.
        return any(".".join(labels[i:]) in self._rules.wildcard_roots for i in range(1, len(labels)))

    def classify_url(self, url: str) -> ScopeClass:
        try:
            parts = urlsplit(url)
        except ValueError:
            return ScopeClass.OUT_OF_SCOPE
        scheme = (parts.scheme or "").lower()
        if scheme and scheme not in self._rules.allowed_schemes:
            return ScopeClass.OUT_OF_SCOPE
        host_class = self.classify_host(parts.hostname)
        if host_class is not ScopeClass.IN_SCOPE:
            return host_class
        port = parts.port or _DEFAULT_PORTS.get(scheme)
        if not self._port_allowed(parts.hostname, port):
            return ScopeClass.OUT_OF_SCOPE
        return ScopeClass.IN_SCOPE

    def classify_service(self, host: str, port: int) -> ScopeClass:
        host_class = self.classify_host(host)
        if host_class is not ScopeClass.IN_SCOPE:
            return host_class
        return ScopeClass.IN_SCOPE if self._port_allowed(host, port) else ScopeClass.OUT_OF_SCOPE

    def _port_allowed(self, hostname: str | None, port: int | None) -> bool:
        if port is None:
            return True
        host = (hostname or "").lower().rstrip(".")
        constraint = self._rules.url_constraints.get(host)
        if constraint is not None and port not in constraint:
            return False
        if self._rules.allowed_ports is not None and port not in self._rules.allowed_ports:
            return False
        return True

    # -- active-interaction gate ------------------------------------------------------

    def may_probe_host(self, hostname: str | None) -> bool:
        """Whether an active request to this host is permitted right now."""
        cls_ = self.classify_host(hostname)
        if cls_ is ScopeClass.IN_SCOPE:
            return True
        if cls_ is ScopeClass.UNKNOWN:
            return self._probe_unknown
        return False

    def may_probe_url(self, url: str) -> bool:
        cls_ = self.classify_url(url)
        if cls_ is ScopeClass.IN_SCOPE:
            return True
        if cls_ is ScopeClass.UNKNOWN:
            return self._probe_unknown
        return False

    @property
    def in_scope_hosts(self) -> set[str]:
        """Exact hosts (wildcard roots are matched dynamically, not enumerated)."""
        return set(self._rules.exact_hosts)

    def probe_urls(self, host: str) -> list[str]:
        """Seed URLs for crawling/enrichment: allowed schemes x constrained-or-default ports."""
        host = host.lower().rstrip(".")
        schemes = sorted(self._rules.allowed_schemes, reverse=True)  # https before http
        ports = sorted(self._rules.url_constraints.get(host, ()))
        urls: list[str] = []
        for scheme in schemes:
            if ports:
                default = _DEFAULT_PORTS.get(scheme)
                for port in ports:
                    suffix = "" if str(port) == str(default) else f":{port}"
                    urls.append(f"{scheme}://{host}{suffix}/")
            else:
                urls.append(f"{scheme}://{host}/")
        return list(dict.fromkeys(urls))

    def monitor_target(self, host: str) -> str:
        """Target string for the monitoring stage.

        A host constrained to one scheme+port is monitored exactly there; an
        unconstrained host is monitored scheme-less (HTTPS first, HTTP fallback).
        """
        host = host.lower().rstrip(".")
        ports = sorted(self._rules.url_constraints.get(host, ()))
        if len(self._rules.allowed_schemes) == 1 and ports:
            scheme = next(iter(self._rules.allowed_schemes))
            default = _DEFAULT_PORTS.get(scheme)
            port = ports[0]
            suffix = "" if str(port) == str(default) else f":{port}"
            return f"{scheme}://{host}{suffix}"
        return host
