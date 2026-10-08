"""Program-level run lock: never two writers against one program workspace.

A lock file records PID, host, start time and a heartbeat. Acquisition fails if
a *live* lock exists. A stale lock (dead PID, or heartbeat far in the past) can
be detected and, with explicit recovery, broken. The lock is always released on
clean exit; crash recovery relies on stale detection rather than a permanent file.
"""

from __future__ import annotations

import json
import os
import socket
import time
from dataclasses import dataclass
from pathlib import Path

STALE_AFTER_SECONDS = 3600.0   # a lock whose heartbeat is older than this is considered abandoned


@dataclass(frozen=True, slots=True)
class LockInfo:
    pid: int
    host: str
    started_at: float
    heartbeat: float

    @property
    def age(self) -> float:
        return time.time() - self.heartbeat


class LockError(RuntimeError):
    pass


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        if os.name == "nt":
            import ctypes
            PROCESS_QUERY_LIMITED = 0x1000
            handle = ctypes.windll.kernel32.OpenProcess(PROCESS_QUERY_LIMITED, False, pid)
            if not handle:
                return False
            exit_code = ctypes.c_ulong()
            ok = ctypes.windll.kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code))
            ctypes.windll.kernel32.CloseHandle(handle)
            return bool(ok) and exit_code.value == 259  # STILL_ACTIVE
        os.kill(pid, 0)
        return True
    except (OSError, Exception):
        return False


def read_lock(path: Path) -> LockInfo | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return LockInfo(int(data["pid"]), str(data["host"]), float(data["started_at"]), float(data["heartbeat"]))
    except (OSError, ValueError, KeyError, TypeError):
        return None


def is_stale(info: LockInfo, *, same_host: bool | None = None) -> bool:
    """A lock is stale if its heartbeat is old, or (on this host) its PID is dead."""
    if info.age > STALE_AFTER_SECONDS:
        return True
    on_this_host = (info.host == socket.gethostname()) if same_host is None else same_host
    if on_this_host and not _pid_alive(info.pid):
        return True
    return False


class RunLock:
    """Context-manager run lock. ``force`` breaks a stale lock (explicit recovery)."""

    def __init__(self, path: Path, *, force: bool = False) -> None:
        self._path = Path(path)
        self._force = force
        self._held = False

    def _write(self) -> None:
        now = time.time()
        payload = {"pid": os.getpid(), "host": socket.gethostname(), "started_at": now, "heartbeat": now}
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_suffix(".lock.tmp")
        tmp.write_text(json.dumps(payload), encoding="utf-8")
        os.replace(tmp, self._path)

    def acquire(self) -> None:
        existing = read_lock(self._path)
        if existing is not None:
            if is_stale(existing) or self._force:
                # Recover: overwrite the stale/forced lock.
                pass
            else:
                raise LockError(
                    f"program is already running (pid={existing.pid} on {existing.host}, "
                    f"age={existing.age:.0f}s); use recovery/--force if this is stale")
        self._write()
        self._held = True

    def heartbeat(self) -> None:
        if not self._held:
            return
        info = read_lock(self._path)
        if info is None:
            return
        payload = {"pid": info.pid, "host": info.host, "started_at": info.started_at, "heartbeat": time.time()}
        try:
            self._path.write_text(json.dumps(payload), encoding="utf-8")
        except OSError:
            pass

    def release(self) -> None:
        if self._held:
            try:
                self._path.unlink(missing_ok=True)
            except OSError:
                pass
            self._held = False

    def __enter__(self) -> "RunLock":
        self.acquire()
        return self

    def __exit__(self, *exc) -> None:
        self.release()
