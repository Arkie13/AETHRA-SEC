"""Detect a frozen interface thread and record where it is stuck.

Why this exists
---------------
The "crash during a high-severity attack" was, on the evidence, not a Python
exception: the log of every affected run simply stops, with no traceback, and
Windows recorded on 14 Oct 2026 04:28:20 (Application log, Event ID 1002,
AppHangB1) that "python.exe stopped interacting with Windows and was closed".
The Tk thread stopped answering the operating system and Windows ended the
process. Exception hooks cannot see that - nothing is raised - which is why
earlier fixes had to be inferred from timing measurements rather than from the
line the thread was actually blocked on.

This module closes that gap. The Tk thread calls :meth:`UiStallWatchdog.beat`
from its own event loop; a separate daemon thread checks the age of the last
beat, and when the loop has been silent for ``threshold`` seconds it writes the
stack of EVERY thread, with process memory and thread counts, to
``logs/ui_stall_<time>.txt`` and logs a warning naming that file. A second dump
is taken if the stall is still going at three times the threshold, so a stall
that moves between call sites is visible as such. When the loop beats again
the duration of the stall is logged.

``faulthandler`` is enabled separately (:func:`enable_fatal_error_log`) for the
other way a process can die silently - a fault inside native code - so the
interpreter's last stacks are written to ``logs/fatal_errors.log``.

It changes nothing about how the application runs. It only observes.
"""

from __future__ import annotations

import faulthandler
import sys
import threading
import time
import traceback
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, TextIO

from aethra_sec.utils.logging import get_logger

LOGGER = get_logger("diagnostics.ui_watchdog")

#: Seconds without a heartbeat before the interface counts as frozen. Windows
#: marks a window "Not Responding" after 5 s of unanswered input.
DEFAULT_THRESHOLD_SECONDS = 5.0
#: How often the watchdog thread looks at the heartbeat.
DEFAULT_POLL_SECONDS = 1.0
#: Stall reports kept on disk; older ones are removed so a recurring stall
#: cannot fill the disk.
MAX_REPORTS = 20

_fatal_log: TextIO | None = None


def enable_fatal_error_log(log_dir: str | Path) -> Path | None:
    """Write native-crash stacks to ``<log_dir>/fatal_errors.log``.

    The file stays open for the life of the process, as ``faulthandler``
    requires. Returns the path, or ``None`` when it could not be enabled.
    """
    global _fatal_log
    path = Path(log_dir) / "fatal_errors.log"
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        if _fatal_log is None or _fatal_log.closed:
            _fatal_log = open(path, "a", encoding="utf-8")  # noqa: SIM115
            _fatal_log.write(f"\n=== process {datetime.now():%Y-%m-%d %H:%M:%S} ===\n")
            _fatal_log.flush()
        faulthandler.enable(file=_fatal_log, all_threads=True)
    except Exception:  # noqa: BLE001 - diagnostics must never stop startup
        LOGGER.warning("Could not enable the fatal error log.", exc_info=True)
        return None
    return path


def thread_stacks() -> str:
    """The current stack of every live thread, named, as text."""
    names = {thread.ident: thread.name for thread in threading.enumerate()}
    blocks = []
    for ident, frame in sys._current_frames().items():  # noqa: SLF001
        blocks.append(
            f"--- thread {names.get(ident, '?')} (ident {ident}) ---\n"
            + "".join(traceback.format_stack(frame))
        )
    return "\n".join(blocks)


def _process_summary() -> str:
    try:
        import psutil

        process = psutil.Process()
        memory = process.memory_info()
        return (
            f"rss={memory.rss / 1e6:.1f} MB vms={memory.vms / 1e6:.1f} MB "
            f"threads={process.num_threads()} cpu_percent="
            f"{process.cpu_percent(interval=None):.0f}"
        )
    except Exception:  # noqa: BLE001
        return f"threads={threading.active_count()} (psutil unavailable)"


class UiStallWatchdog:
    """Watches a heartbeat from the Tk thread and records stalls."""

    def __init__(
        self,
        log_dir: str | Path,
        *,
        threshold: float = DEFAULT_THRESHOLD_SECONDS,
        poll: float = DEFAULT_POLL_SECONDS,
        clock: Callable[[], float] = time.monotonic,
        stacks: Callable[[], str] = thread_stacks,
        context: Callable[[], str] | None = None,
    ) -> None:
        self._dir = Path(log_dir)
        self._threshold = max(0.5, float(threshold))
        self._poll = max(0.05, float(poll))
        self._clock = clock
        self._stacks = stacks
        #: Extra lines for a report - e.g. event-bus backlog. Never required.
        self._context = context
        self._last_beat = clock()
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._stall_started: float | None = None
        self._dumps_this_stall = 0
        self.stalls = 0
        self.reports: list[Path] = []

    # -- called on the Tk thread -------------------------------------------
    def beat(self) -> None:
        """Record that the interface loop ran. Cheap: one clock read."""
        with self._lock:
            self._last_beat = self._clock()

    # -- lifecycle ------------------------------------------------------------
    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(
            target=self._run, name="ui-stall-watchdog", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _run(self) -> None:
        while not self._stop.wait(self._poll):
            try:
                self.check()
            except Exception:  # noqa: BLE001 - the watchdog must not die
                LOGGER.exception("UI stall watchdog check failed.")

    # -- the decision -----------------------------------------------------------
    def check(self) -> Path | None:
        """Look at the heartbeat once. Returns a report path when one is written."""
        now = self._clock()
        with self._lock:
            age = now - self._last_beat
            last = self._last_beat
        if age < self._threshold:
            if self._stall_started is not None:
                LOGGER.warning(
                    "[UI-STALL] The interface responded again after %.1f s "
                    "without running its event loop.",
                    now - self._stall_started,
                )
                self._stall_started = None
                self._dumps_this_stall = 0
            return None
        if self._stall_started is None:
            self._stall_started = last
            self.stalls += 1
        due = self._threshold * (3 ** self._dumps_this_stall)
        if self._dumps_this_stall >= 2 or age < due:
            return None
        self._dumps_this_stall += 1
        return self._report(age)

    def _report(self, age: float) -> Path | None:
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = self._dir / f"ui_stall_{stamp}_{self._dumps_this_stall}.txt"
        # Stacks first: they are the point of the report, and taking them
        # needs no lock the stuck thread could be holding.
        stacks = self._stacks()
        lines = [
            f"AETHRA-SEC interface stall report - {datetime.now():%Y-%m-%d %H:%M:%S}",
            f"The Tk event loop has not run for {age:.1f} s "
            f"(threshold {self._threshold:.1f} s).",
            f"Process: {_process_summary()}",
            f"Context: {self._bounded_context()}",
            "", "The thread named MainThread is the Tk thread. Its stack is "
            "where the interface is stuck.", "", stacks,
        ]
        try:
            self._dir.mkdir(parents=True, exist_ok=True)
            path.write_text("\n".join(lines), encoding="utf-8")
        except OSError:
            LOGGER.exception("Could not write a UI stall report.")
            return None
        self.reports.append(path)
        self._trim_reports()
        LOGGER.warning(
            "[UI-STALL] The interface has not run its event loop for %.1f s. "
            "Every thread's stack was written to %s.",
            age, path,
        )
        return path

    def _bounded_context(self, timeout: float = 1.0) -> str:
        """The optional context, abandoned after ``timeout`` seconds.

        The context may take a lock (the event bus's) that the stuck Tk thread
        holds; waiting for it would stop the watchdog writing anything at all.
        """
        if self._context is None:
            return "none supplied"
        result: list[str] = []

        def collect() -> None:
            try:
                result.append(str(self._context()))
            except Exception as exc:  # noqa: BLE001
                result.append(f"unavailable ({exc})")

        worker = threading.Thread(target=collect, name="ui-stall-context", daemon=True)
        worker.start()
        worker.join(timeout)
        return result[0] if result else f"not collected within {timeout:.0f} s (a lock is held)"

    def _trim_reports(self) -> None:
        try:
            existing = sorted(self._dir.glob("ui_stall_*.txt"))
        except OSError:
            return
        for old in existing[:-MAX_REPORTS]:
            try:
                old.unlink()
            except OSError:
                pass


def install_on_tk(root: Any, watchdog: UiStallWatchdog, interval_ms: int = 500) -> Callable[[], None]:
    """Beat the watchdog from ``root``'s event loop. Returns a cancel function."""
    state: dict[str, Any] = {"job": None, "stopped": False}

    def tick() -> None:
        if state["stopped"]:
            return
        watchdog.beat()
        try:
            state["job"] = root.after(interval_ms, tick)
        except Exception:  # noqa: BLE001 - the window is closing
            state["stopped"] = True

    def cancel() -> None:
        state["stopped"] = True
        watchdog.stop()
        if state["job"] is not None:
            try:
                root.after_cancel(state["job"])
            except Exception:  # noqa: BLE001
                pass

    watchdog.beat()
    watchdog.start()
    tick()
    return cancel
