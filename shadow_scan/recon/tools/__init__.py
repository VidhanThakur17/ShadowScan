"""External recon-tool adapters (all optional, all behind safe subprocess arrays)."""

from .adapters import (
    DISCOVERY_ADAPTERS,
    PORT_ADAPTERS,
    URL_ADAPTERS,
    Amass,
    Findomain,
    Gau,
    Naabu,
    Nmap,
    Subfinder,
    Waybackurls,
    available_adapters,
)
from .base import ProcessRunner, ToolAdapter, ToolResult, subprocess_runner

__all__ = [
    "ToolAdapter", "ToolResult", "ProcessRunner", "subprocess_runner",
    "Subfinder", "Amass", "Findomain", "Gau", "Waybackurls", "Naabu", "Nmap",
    "DISCOVERY_ADAPTERS", "URL_ADAPTERS", "PORT_ADAPTERS", "available_adapters",
]
