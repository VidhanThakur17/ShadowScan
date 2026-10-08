"""Asynchronous DNS resolution and historical transition detection.

Resolution is bounded by a semaphore and runs ``getaddrinfo`` in the event
loop's default executor, so no third-party DNS dependency is required. A
pluggable :class:`Resolver` keeps this fully offline-testable: tests inject a
fake resolver and never touch the network.

The stdlib can give us A/AAAA addresses and the canonical name
(``AI_CANONNAME``); it cannot cheaply return the full intermediate CNAME chain,
so ``cname_chain`` holds the canonical target when it differs from the queried
name. :func:`dns_transitions` is pure and compares two :class:`DnsRecord`
snapshots into recon events.

A dangling-looking CNAME (resolves to a name but yields no address) is surfaced
as a *review signal* only — never a takeover claim.
"""

from __future__ import annotations

import asyncio
import logging
import socket
from collections.abc import Iterable, Sequence
from typing import Protocol

from .models import DnsRecord, ReconEvent

logger = logging.getLogger(__name__)


class Resolver(Protocol):
    async def resolve(self, hostname: str) -> DnsRecord: ...


class StdlibResolver:
    """Resolves via ``loop.getaddrinfo`` in the default executor."""

    def __init__(self, timeout: float = 5.0) -> None:
        self._timeout = timeout

    async def resolve(self, hostname: str) -> DnsRecord:
        loop = asyncio.get_running_loop()
        try:
            infos = await asyncio.wait_for(
                loop.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP, flags=socket.AI_CANONNAME),
                timeout=self._timeout,
            )
        except asyncio.TimeoutError:
            return DnsRecord(hostname, status="error", error="timeout")
        except socket.gaierror as exc:
            status = "nxdomain" if exc.errno in (socket.EAI_NONAME, getattr(socket, "EAI_NODATA", -5)) else "error"
            return DnsRecord(hostname, status=status, error=str(exc))
        except OSError as exc:
            return DnsRecord(hostname, status="error", error=str(exc))

        a: list[str] = []
        aaaa: list[str] = []
        canonical = ""
        for family, _type, _proto, canonname, sockaddr in infos:
            if canonname:
                canonical = canonname.rstrip(".")
            addr = sockaddr[0]
            if family == socket.AF_INET and addr not in a:
                a.append(addr)
            elif family == socket.AF_INET6 and addr not in aaaa:
                aaaa.append(addr)
        cname_chain: tuple[str, ...] = ()
        if canonical and canonical.lower() != hostname.lower().rstrip("."):
            cname_chain = (canonical,)
        if not a and not aaaa:
            return DnsRecord(hostname, status="nxdomain", cname_chain=cname_chain)
        return DnsRecord(hostname, status="resolves", a=tuple(sorted(a)),
                         aaaa=tuple(sorted(aaaa)), cname_chain=cname_chain)


async def resolve_all(
    hostnames: Iterable[str],
    resolver: Resolver,
    *,
    concurrency: int = 50,
) -> list[DnsRecord]:
    """Resolve many hostnames with bounded concurrency. One record per host."""
    unique = list(dict.fromkeys(h.lower().rstrip(".") for h in hostnames if h))
    semaphore = asyncio.Semaphore(max(1, concurrency))

    async def one(host: str) -> DnsRecord:
        async with semaphore:
            try:
                return await resolver.resolve(host)
            except Exception as exc:  # a resolver bug must not kill the batch
                logger.debug("Resolver error for %s: %s", host, exc)
                return DnsRecord(host, status="error", error=str(exc))

    return list(await asyncio.gather(*(one(h) for h in unique)))


def is_dangling(record: DnsRecord) -> bool:
    """CNAME target present but nothing resolves to an address. Review signal only."""
    return record.status != "resolves" and bool(record.cname_chain)


def dns_transitions(previous: DnsRecord | None, current: DnsRecord) -> list[ReconEvent]:
    """Pure comparison of two DNS snapshots into recon events."""
    events: list[ReconEvent] = []
    if previous is None:
        events.append(ReconEvent.NEW_SUBDOMAIN)
        if current.resolves:
            events.append(ReconEvent.DNS_BECAME_LIVE)
        if is_dangling(current):
            events.append(ReconEvent.DANGLING_CNAME)
        return events

    if not previous.resolves and current.resolves:
        events.append(ReconEvent.DNS_BECAME_LIVE)
    elif previous.resolves and not current.resolves:
        events.append(ReconEvent.DNS_BECAME_DEAD)

    if previous.terminal_cname != current.terminal_cname and (previous.terminal_cname or current.terminal_cname):
        events.append(ReconEvent.CNAME_CHANGED)

    if current.resolves and previous.resolves:
        old_ips = set(previous.a) | set(previous.aaaa)
        new_ips = set(current.a) | set(current.aaaa)
        if old_ips != new_ips:
            events.append(ReconEvent.IP_CHANGED)

    if is_dangling(current) and not is_dangling(previous):
        events.append(ReconEvent.DANGLING_CNAME)
    return events


def hosts_to_monitor(records: Sequence[DnsRecord]) -> list[str]:
    """In-scope hosts that currently resolve, ready to feed the HTTP monitor."""
    return [r.hostname for r in records if r.resolves]
