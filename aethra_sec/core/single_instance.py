"""One running console per machine user.

Every AETHRA-SEC process starts the whole background stack: the scheduler, the
assessment queue, Snort ingest, retention, backups. Two consoles open at once
therefore run two assessment queues against the same inventory - each deciding
independently that the same host is due and starting its own Nmap process -
and two Snort ingest loops reading the same alert file into the same table.

This was observed, not hypothesised: three consoles were found running on the
development machine at once, launched minutes apart from the desktop shortcut.

The guard is a named kernel object on Windows (a mutex in the session
namespace) and an exclusive file lock elsewhere. Both are released by the
operating system when the process ends however it ends, so a crash can never
leave a stale lock that blocks the next start.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from aethra_sec.utils.logging import get_logger

LOGGER = get_logger("core.single_instance")

#: Session-local on Windows: one console per signed-in Windows user session.
MUTEX_NAME = "Local\\AETHRA-SEC.console"
_ERROR_ALREADY_EXISTS = 183

_held: Any = None


def acquire(lock_dir: Path | None = None) -> bool:
    """Claim the single-instance lock for this process.

    Returns:
        True when this process now holds it; False when another AETHRA-SEC
        console already does. Any failure to *create* the lock is logged and
        treated as acquired - the guard exists to prevent duplication, and it
        must never be the reason the application cannot start at all.
    """
    global _held
    if _held is not None:
        return True
    if os.name == "nt":
        return _acquire_windows()
    return _acquire_posix(lock_dir)


def _acquire_windows() -> bool:
    global _held
    try:
        import ctypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateMutexW.restype = ctypes.c_void_p
        handle = kernel32.CreateMutexW(None, False, MUTEX_NAME)
        error = ctypes.get_last_error()
    except Exception:  # noqa: BLE001
        LOGGER.warning("Single-instance guard unavailable.", exc_info=True)
        return True
    if not handle:
        LOGGER.warning("CreateMutex failed (%s); continuing without the guard.", error)
        return True
    if error == _ERROR_ALREADY_EXISTS:
        kernel32.CloseHandle(ctypes.c_void_p(handle))
        return False
    _held = handle
    return True


def _acquire_posix(lock_dir: Path | None) -> bool:
    global _held
    try:
        import fcntl

        directory = lock_dir or Path.home()
        directory.mkdir(parents=True, exist_ok=True)
        handle = open(directory / ".aethra-sec.lock", "a+")  # noqa: SIM115
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            handle.close()
            return False
    except Exception:  # noqa: BLE001
        LOGGER.warning("Single-instance guard unavailable.", exc_info=True)
        return True
    _held = handle
    return True


def is_held() -> bool:
    """True when this process holds the lock."""
    return _held is not None
