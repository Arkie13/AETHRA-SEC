"""Tie capture children to the life of this process (§61).

Terminating capture cleanly is handled by the reader. This covers the case the
reader cannot: the console itself being killed - Task Manager, ``Stop-Process
-Force``, a crash - where no Python code runs at all and ``dumpcap`` is left
holding the adapter open, still capturing, invisible to the operator who
believes they closed the application.

Windows answers this with a Job Object. A job carrying
``JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`` terminates every process in it when the
last handle to the job closes, and the handle closes when this process dies
however it dies. The kernel does the cleanup, so it does not depend on an exit
path being reached.

On any non-Windows platform, and on a Windows without the API, every function
here is a no-op: the caller's behaviour is unchanged and nothing raises.
"""

from __future__ import annotations

import os
import threading
from typing import Any

from aethra_sec.utils.logging import get_logger

LOGGER = get_logger("integrations.pyshark.jobs")

#: Terminate every process in the job when the last handle to it closes.
_KILL_ON_JOB_CLOSE = 0x00002000
#: JobObjectExtendedLimitInformation
_EXTENDED_LIMIT_INFORMATION = 9

_lock = threading.Lock()
_job: Any = None
_unavailable = False


def _build_job() -> Any:
    """Create the process-wide job, or return ``None`` when unavailable."""
    import ctypes
    import ctypes.wintypes as wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    class _BasicLimits(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_int64),
            ("PerJobUserTimeLimit", ctypes.c_int64),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.POINTER(ctypes.c_ulong)),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class _IoCounters(ctypes.Structure):
        _fields_ = [
            (name, ctypes.c_uint64)
            for name in (
                "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
                "ReadTransferCount", "WriteTransferCount", "OtherTransferCount",
            )
        ]

    class _ExtendedLimits(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", _BasicLimits),
            ("IoInfo", _IoCounters),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    handle = kernel32.CreateJobObjectW(None, None)
    if not handle:
        LOGGER.debug("CreateJobObject failed (%s).", ctypes.get_last_error())
        return None

    limits = _ExtendedLimits()
    limits.BasicLimitInformation.LimitFlags = _KILL_ON_JOB_CLOSE
    if not kernel32.SetInformationJobObject(
        handle, _EXTENDED_LIMIT_INFORMATION, ctypes.byref(limits), ctypes.sizeof(limits)
    ):
        LOGGER.debug("SetInformationJobObject failed (%s).", ctypes.get_last_error())
        kernel32.CloseHandle(handle)
        return None

    LOGGER.info(
        "Capture children will be terminated by the kernel if this process dies."
    )
    return handle


def _job_handle() -> Any:
    """The process-wide job handle, created once, or ``None``."""
    global _job, _unavailable
    if _unavailable:
        return None
    with _lock:
        if _job is None:
            if os.name != "nt":
                _unavailable = True
                return None
            try:
                _job = _build_job()
            except Exception:  # noqa: BLE001 - hardening must never break capture
                LOGGER.debug("Job Object unavailable.", exc_info=True)
                _job = None
            if _job is None:
                _unavailable = True
        return _job


def adopt(pid: int) -> bool:
    """Put ``pid`` under this process's job, so the kernel reaps it.

    A process already in the job is reported as adopted. Failure is never
    raised: this is hardening layered over an orderly stop that already works,
    and a capture must not fail because the extra safety net could not be hung.

    Args:
        pid: the capture child to adopt.

    Returns:
        True when the process is now covered by the job.
    """
    handle = _job_handle()
    if handle is None or pid <= 0:
        return False
    try:
        import ctypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        # PROCESS_SET_QUOTA | PROCESS_TERMINATE
        process = kernel32.OpenProcess(0x0100 | 0x0001, False, int(pid))
        if not process:
            return False
        try:
            if kernel32.AssignProcessToJobObject(handle, process):
                return True
            # ERROR_ACCESS_DENIED here usually means "already in this job",
            # which is the outcome we wanted anyway.
            return ctypes.get_last_error() == 5
        finally:
            kernel32.CloseHandle(process)
    except Exception:  # noqa: BLE001
        LOGGER.debug("Could not adopt pid %s into the job.", pid, exc_info=True)
        return False


def is_active() -> bool:
    """True when a job is in place and capture children are being adopted."""
    return _job_handle() is not None
