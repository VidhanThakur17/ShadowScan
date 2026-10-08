"""Concrete adapters for commonly installed recon binaries.

Each adapter only knows how to (a) build a safe argument array for a set of
targets and (b) parse the tool's stdout. None of them are required to exist;
the registry filters to whatever is installed.

Discovery adapters emit hostnames. URL adapters emit URLs. The port adapter
emits ``host:port`` strings. Hostname/URL normalization and scope validation
happen in the pipeline, not here.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator

from .base import ToolAdapter, ToolResult, line_items

# --- passive subdomain discovery --------------------------------------------------------


class Subfinder(ToolAdapter):
    name = "subfinder"
    version_args = ("-version",)

    def build_args(self, targets: Iterable[str]) -> list[str]:
        args = ["subfinder", "-silent"]
        for target in targets:
            args += ["-d", target]
        return args

    def parse(self, result: ToolResult) -> Iterator[str]:
        yield from line_items(result)


class Amass(ToolAdapter):
    name = "amass"
    version_args = ("-version",)

    def build_args(self, targets: Iterable[str]) -> list[str]:
        # Passive mode only: no active resolution or brute force.
        args = ["amass", "enum", "-passive", "-silent"]
        for target in targets:
            args += ["-d", target]
        return args

    def parse(self, result: ToolResult) -> Iterator[str]:
        yield from line_items(result)


class Findomain(ToolAdapter):
    name = "findomain"
    version_args = ("--version",)

    def build_args(self, targets: Iterable[str]) -> list[str]:
        args = ["findomain", "--quiet"]
        for target in targets:
            args += ["-t", target]
        return args

    def parse(self, result: ToolResult) -> Iterator[str]:
        yield from line_items(result)


# --- passive URL collection -------------------------------------------------------------


class Gau(ToolAdapter):
    name = "gau"
    version_args = ("--version",)

    def build_args(self, targets: Iterable[str]) -> list[str]:
        return ["gau", "--threads", "4", *targets]

    def parse(self, result: ToolResult) -> Iterator[str]:
        for line in line_items(result):
            # gau can emit JSON lines with -json, but default is plain URLs.
            yield line


class Waybackurls(ToolAdapter):
    name = "waybackurls"
    version_args = ("-h",)

    def build_args(self, targets: Iterable[str]) -> list[str]:
        # waybackurls reads domains from stdin or takes a single arg; we pass args.
        return ["waybackurls", *targets]

    def parse(self, result: ToolResult) -> Iterator[str]:
        yield from line_items(result)


# --- bounded port / service discovery ---------------------------------------------------


class Naabu(ToolAdapter):
    name = "naabu"
    version_args = ("-version",)

    def __init__(self, *args, ports: str = "80,443,8080,8443,8000,8888", **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._ports = ports

    def build_args(self, targets: Iterable[str]) -> list[str]:
        args = ["naabu", "-silent", "-p", self._ports]
        for target in targets:
            args += ["-host", target]
        return args

    def parse(self, result: ToolResult) -> Iterator[str]:
        # naabu prints host:port per line.
        for line in line_items(result):
            if ":" in line:
                yield line


class Nmap(ToolAdapter):
    name = "nmap"
    version_args = ("--version",)

    def __init__(self, *args, ports: str = "80,443,8080,8443,8000,8888", **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._ports = ports

    def build_args(self, targets: Iterable[str]) -> list[str]:
        # -sT connect scan, -Pn skip host discovery, -oG greppable to stdout.
        # No version/script scanning: conservative and non-aggressive.
        return ["nmap", "-Pn", "-sT", "-p", self._ports, "-oG", "-", *targets]

    def parse(self, result: ToolResult) -> Iterator[str]:
        for line in result.stdout.splitlines():
            if "Ports:" not in line or not line.startswith("Host:"):
                continue
            try:
                host = line.split()[1]
                ports_part = line.split("Ports:", 1)[1]
            except IndexError:
                continue
            for entry in ports_part.split(","):
                fields = entry.strip().split("/")
                if len(fields) >= 2 and fields[1] == "open":
                    yield f"{host}:{fields[0]}"


# --- registry ---------------------------------------------------------------------------

DISCOVERY_ADAPTERS: tuple[type[ToolAdapter], ...] = (Subfinder, Amass, Findomain)
URL_ADAPTERS: tuple[type[ToolAdapter], ...] = (Gau, Waybackurls)
PORT_ADAPTERS: tuple[type[ToolAdapter], ...] = (Naabu, Nmap)


def available_adapters(
    adapters: Iterable[type[ToolAdapter]],
    runner=None,
) -> list[ToolAdapter]:
    """Instantiate adapters and keep only the ones whose binary is present."""
    instances = []
    for adapter_cls in adapters:
        instance = adapter_cls(runner=runner) if runner is not None else adapter_cls()
        if instance.available():
            instances.append(instance)
    return instances
