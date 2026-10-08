"""Base class for external-tool adapters.

Safety rules enforced here:

* Commands are always **argument arrays** passed to ``subprocess.run`` with
  ``shell=False``. There is no shell-string concatenation anywhere, so target
  names cannot inject commands.
* Every execution is bounded by a timeout and captures stdout/stderr.
* A missing binary degrades gracefully: :meth:`available` returns ``False`` and
  :meth:`run` yields nothing instead of raising.

Adapters are offline-testable: :meth:`run` resolves the binary via an injected
``runner`` callable, so tests feed canned process output without real binaries.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from typing import Protocol

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 300.0
_MAX_OUTPUT_BYTES = 64 * 1024 * 1024   # guard against a runaway tool filling memory


@dataclass(frozen=True, slots=True)
class ToolResult:
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out


class ProcessRunner(Protocol):
    def __call__(self, args: list[str], timeout: float) -> ToolResult: ...


def subprocess_runner(args: list[str], timeout: float) -> ToolResult:
    """Default runner: a real, bounded, shell-free subprocess call."""
    try:
        proc = subprocess.run(  # noqa: S603 - args is a list, shell=False, no user shell string
            args,
            capture_output=True,
            # Decode as UTF-8 with replacement rather than the OS locale codec
            # (cp1252 on Windows), which raises on arbitrary tool output bytes.
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            shell=False,
            check=False,
        )
    except FileNotFoundError:
        return ToolResult(127, "", "binary not found")
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout or ""
        err = exc.stderr or ""
        out = out.decode(errors="replace") if isinstance(out, bytes) else out
        err = err.decode(errors="replace") if isinstance(err, bytes) else err
        return ToolResult(-1, out[:_MAX_OUTPUT_BYTES], err, timed_out=True)
    return ToolResult(proc.returncode, (proc.stdout or "")[:_MAX_OUTPUT_BYTES], proc.stderr or "")


class ToolAdapter:
    """One external recon binary. Subclasses set ``name`` and implement parsing."""

    name: str = ""
    version_args: tuple[str, ...] = ("-version",)

    def __init__(self, runner: ProcessRunner = subprocess_runner, binary: str | None = None) -> None:
        self._runner = runner
        self._binary = binary or self.name

    def available(self) -> bool:
        """True when the binary is resolvable on PATH (or an explicit path exists)."""
        return shutil.which(self._binary) is not None or (
            self._binary not in (None, self.name) and bool(self._binary)
        )

    def version(self) -> str | None:
        if not self.available():
            return None
        result = self._runner([self._binary, *self.version_args], 15.0)
        text = (result.stdout or result.stderr).strip()
        return text.splitlines()[0] if text else None

    def build_args(self, targets: Iterable[str]) -> list[str]:  # pragma: no cover - overridden
        raise NotImplementedError

    def parse(self, result: ToolResult) -> Iterator[str]:  # pragma: no cover - overridden
        raise NotImplementedError

    def run(self, targets: Iterable[str], timeout: float = DEFAULT_TIMEOUT) -> list[str]:
        """Execute the tool and return parsed, de-duplicated results.

        Missing or failed tools return ``[]`` and log at DEBUG/WARNING rather
        than raising, so one absent binary never aborts a recon run.
        """
        targets = list(targets)
        if not targets:
            return []
        if not self.available():
            logger.debug("Tool %s not available; skipping", self.name)
            return []
        args = self.build_args(targets)
        result = self._runner(args, timeout)
        if result.timed_out:
            logger.warning("Tool %s timed out after %.0fs; using partial output", self.name, timeout)
        elif not result.ok:
            logger.warning("Tool %s exited %d: %s", self.name, result.returncode, result.stderr.strip()[:200])
        seen: set[str] = set()
        out: list[str] = []
        for item in self.parse(result):
            if item and item not in seen:
                seen.add(item)
                out.append(item)
        return out


def line_items(result: ToolResult) -> Iterator[str]:
    """Yield stripped, non-empty stdout lines. Shared by line-oriented tools."""
    for line in result.stdout.splitlines():
        stripped = line.strip()
        if stripped:
            yield stripped
