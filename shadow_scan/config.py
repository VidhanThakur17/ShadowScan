"""Runtime configuration.

The module-level constants are the defaults; edit them here to change the
out-of-the-box behaviour, or override them per run through the CLI.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from . import __version__

# --- Performance / safety defaults -------------------------------------------------
MAX_CONCURRENCY = 100                    # simultaneous in-flight targets
REQUEST_TIMEOUT = 10                     # seconds: connect (incl. DNS) and per-socket-read
TOTAL_REQUEST_TIMEOUT = 30               # seconds: hard ceiling for one HTTP request (one hop)
MAX_RESPONSE_BYTES = 5 * 1024 * 1024     # body bytes read per response before we stop
MAX_REDIRECTS = 5                        # in-scope redirect hops followed per target

# --- Persistence defaults ----------------------------------------------------------
DB_BATCH_SIZE = 200                      # observations committed per transaction
DB_FLUSH_INTERVAL = 2.0                  # seconds before a partial batch is committed

# --- Phase 2: noise reduction & delta intelligence ---------------------------------
NORMALIZATION_MAX_BYTES = 1024 * 1024    # text bodies above this get no normalized hash (raw only)
SIMILARITY_MAX_BYTES = 512 * 1024        # normalized text above this gets no similarity sketch
SIMILARITY_CHUNK_DIVISOR = 8             # ~tokens per similarity chunk (sketch = 4 bytes per chunk)
CPU_OFFLOAD_BYTES = 64 * 1024            # bodies above this are normalized in a worker thread
# similarity >= TRIVIAL: cosmetic/noisy; MAJOR <= similarity < TRIVIAL: minor; below MAJOR: major.
SIMILARITY_TRIVIAL_THRESHOLD = 0.98
SIMILARITY_MAJOR_THRESHOLD = 0.80
CONSOLE_PRIORITY_THRESHOLD = 40          # live [CHANGE] lines below this priority need --verbose
TOP_CHANGES_SHOWN = 10                   # changes listed in the end-of-run console summary

# --- Misc --------------------------------------------------------------------------
TITLE_SCAN_BYTES = 256 * 1024            # only the head of an HTML body is searched for <title>
PROGRESS_INTERVAL = 1000                 # log progress every N completed targets
DEFAULT_USER_AGENT = f"ShadowScan/{__version__} (authorized security monitoring)"


@dataclass(frozen=True, slots=True)
class ScanConfig:
    """All tunables for a single monitoring run."""

    input_path: Path = Path("domains.txt")
    database_path: Path = Path("shadowscan.db")
    output_path: Path = Path("deltas.json")

    concurrency: int = MAX_CONCURRENCY
    request_timeout: float = REQUEST_TIMEOUT
    total_timeout: float = TOTAL_REQUEST_TIMEOUT
    max_response_bytes: int = MAX_RESPONSE_BYTES
    max_redirects: int = MAX_REDIRECTS

    # Scheme-less targets try HTTPS first; when HTTPS is unavailable at the
    # transport level (refused / timeout / TLS failure) fall back to HTTP.
    http_fallback: bool = True
    verify_tls: bool = True
    # By default redirects are only followed to hostnames that appear verbatim
    # in the input list. Enabling this also allows subdomains of those hosts.
    allow_subdomain_redirects: bool = False

    user_agent: str = DEFAULT_USER_AGENT
    # Extra request headers, e.g. a bug bounty program's identification header.
    extra_headers: tuple[tuple[str, str], ...] = ()

    db_batch_size: int = DB_BATCH_SIZE
    db_flush_interval: float = DB_FLUSH_INTERVAL
    title_scan_bytes: int = TITLE_SCAN_BYTES
    progress_interval: int = PROGRESS_INTERVAL

    normalization_max_bytes: int = NORMALIZATION_MAX_BYTES
    similarity_max_bytes: int = SIMILARITY_MAX_BYTES
    similarity_chunk_divisor: int = SIMILARITY_CHUNK_DIVISOR
    cpu_offload_bytes: int = CPU_OFFLOAD_BYTES
    similarity_trivial_threshold: float = SIMILARITY_TRIVIAL_THRESHOLD
    similarity_major_threshold: float = SIMILARITY_MAJOR_THRESHOLD
    console_priority_threshold: int = CONSOLE_PRIORITY_THRESHOLD
    top_changes_shown: int = TOP_CHANGES_SHOWN

    def validate(self) -> None:
        """Raise ``ValueError`` if any setting is outside a sane range."""
        positive = {
            "concurrency": self.concurrency,
            "request_timeout": self.request_timeout,
            "total_timeout": self.total_timeout,
            "max_response_bytes": self.max_response_bytes,
            "db_batch_size": self.db_batch_size,
            "db_flush_interval": self.db_flush_interval,
            "title_scan_bytes": self.title_scan_bytes,
            "progress_interval": self.progress_interval,
            "normalization_max_bytes": self.normalization_max_bytes,
            "similarity_max_bytes": self.similarity_max_bytes,
            "similarity_chunk_divisor": self.similarity_chunk_divisor,
        }
        for name, value in positive.items():
            if value <= 0:
                raise ValueError(f"{name} must be greater than zero (got {value})")
        if self.max_redirects < 0:
            raise ValueError(f"max_redirects must be >= 0 (got {self.max_redirects})")
        if not 0.0 < self.similarity_major_threshold <= self.similarity_trivial_threshold <= 1.0:
            raise ValueError("similarity thresholds must satisfy 0 < major <= trivial <= 1")
        if self.total_timeout < self.request_timeout:
            raise ValueError("total_timeout must be >= request_timeout")
