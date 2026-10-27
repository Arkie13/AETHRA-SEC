"""Measure what a flood actually does to a running AETHRA-SEC (§2, §4).

A report that the application "froze" is a symptom, not a diagnosis. This
module records the evidence needed to turn one into the other, from inside the
running process, while the operator drives a real authorised flood.

The metric that decides is **Tk main-loop lag**. A Tk callback scheduled with
``after(n)`` can only run once the main loop is free, so the amount by which it
arrives late *is* the time the interface spent unresponsive - measured, not
inferred from a queue depth or a CPU figure that might mean anything. Everything
else recorded here exists to explain a lag spike once one is seen:

* capture queue depth, and the reader's own captured/dropped/decode-error
  counters, so shedding is attributed to the stage that shed;
* the display buffer and visible row count of the traffic screen, so a UI
  stall can be separated from a capture stall;
* resident memory, thread count and TShark child count, so a leak or a
  duplicated capture process is visible as it happens;
* database round-trip latency, sampled off the Tk thread, because a blocking
  write is the classic cause of a frozen desktop UI.

Nothing here is enabled by default. The probe starts only when the environment
variable ``AETHRA_FLOOD_PROBE`` is set, so an ordinary run pays nothing for it,
and it writes one CSV to the log directory rather than touching the database.
It reads state and never mutates it: no queue is drained, no counter reset, no
capture setting changed.

The lag sampler reports the **worst** lag observed in each window rather than
the lag of the final tick. A four-second stall that falls between two samples
would otherwise be invisible, which is precisely the event being hunted.

Usage::

    set AETHRA_FLOOD_PROBE=1
    run.bat
    ...run the authorised flood...

Output: ``logs/flood_probe_<timestamp>.csv``
"""

from __future__ import annotations

import os
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from aethra_sec.utils.logging import get_logger

LOGGER = get_logger("diagnostics.flood_probe")

#: Environment variable that arms the probe. Absent or empty: nothing runs.
ENV_FLAG = "AETHRA_FLOOD_PROBE"

#: How often the Tk sampler asks to be woken. Small enough to resolve a stall,
#: large enough that the sampler is not itself a load on the loop it measures.
TICK_MS = 100

#: How often a row is written. One row per second keeps the file readable over
#: a long test while the lag column still carries the worst tick within it.
WINDOW_SECONDS = 1.0

COLUMNS = (
    "elapsed_s",
    "wall_clock",
    "tk_lag_max_ms",
    "tk_lag_mean_ms",
    "tk_ticks",
    "capture_state",
    "captured",
    "dropped",
    "decode_errors",
    "sampled_out",
    "persisted",
    "queue_depth",
    "ui_buffer",
    "ui_buffer_dropped",
    "ui_rows",
    "rss_mb",
    "threads",
    "tshark_children",
    "db_ping_ms",
)


def enabled() -> bool:
    """True when the operator armed the probe for this run."""
    return bool(os.environ.get(ENV_FLAG, "").strip())


def _safe(call: Callable[[], Any], default: Any = "") -> Any:
    """Read a value that may not exist yet, without disturbing the run.

    The probe observes a live application during the worst moment it has; a
    diagnostic that raises into the Tk loop it is measuring would destroy the
    evidence it exists to collect.
    """
    try:
        return call()
    except Exception:  # noqa: BLE001 - a probe must never break the subject
        return default


class FloodProbe:
    """Samples a running application and writes one CSV row per window."""

    def __init__(self, root: Any, context: Any, log_dir: Path | str = "logs") -> None:
        self._root = root
        self._context = context
        self._started = time.monotonic()
        self._stop = threading.Event()

        #: Worst and total lag inside the current window, owned by the Tk
        #: thread and read by it alone.
        self._lag_max = 0.0
        self._lag_sum = 0.0
        self._lag_ticks = 0
        self._last_tick = time.monotonic()
        self._window_started = time.monotonic()

        #: Written by the worker, read by the Tk thread. A stale value is
        #: acceptable; blocking the loop to get a fresh one is not.
        self._lock = threading.Lock()
        self._system: dict[str, Any] = {}

        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        directory = Path(log_dir)
        directory.mkdir(parents=True, exist_ok=True)
        self.path = directory / f"flood_probe_{stamp}.csv"
        self._handle = self.path.open("w", encoding="utf-8", newline="")
        self._handle.write(",".join(COLUMNS) + "\n")
        self._handle.flush()

        self._worker = threading.Thread(
            target=self._sample_system, name="flood-probe", daemon=True
        )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    def start(self) -> None:
        LOGGER.warning(
            "Flood probe ARMED (%s set). Writing %s", ENV_FLAG, self.path
        )
        self._worker.start()
        self._schedule()

    def stop(self) -> None:
        self._stop.set()
        try:
            self._handle.flush()
            self._handle.close()
        except OSError:
            pass

    def _schedule(self) -> None:
        if self._stop.is_set():
            return
        try:
            self._root.after(TICK_MS, self._tick)
        except Exception:  # noqa: BLE001 - the root is going away
            self._stop.set()

    # ------------------------------------------------------------------
    # Tk thread: the lag measurement
    # ------------------------------------------------------------------
    def _tick(self) -> None:
        """Runs on the Tk thread. Its lateness is the measurement."""
        now = time.monotonic()
        lag_ms = max(0.0, (now - self._last_tick) * 1000.0 - TICK_MS)
        self._last_tick = now
        self._lag_max = max(self._lag_max, lag_ms)
        self._lag_sum += lag_ms
        self._lag_ticks += 1

        if now - self._window_started >= WINDOW_SECONDS:
            self._write_row(now)
            self._window_started = now
            self._lag_max = 0.0
            self._lag_sum = 0.0
            self._lag_ticks = 0
        self._schedule()

    def _write_row(self, now: float) -> None:
        capture = _safe(lambda: self._context.capture.statistics(), None)
        screen = self._traffic_screen()
        with self._lock:
            system = dict(self._system)

        row = {
            "elapsed_s": f"{now - self._started:.1f}",
            "wall_clock": datetime.now().strftime("%H:%M:%S"),
            "tk_lag_max_ms": f"{self._lag_max:.1f}",
            "tk_lag_mean_ms": (
                f"{self._lag_sum / self._lag_ticks:.1f}" if self._lag_ticks else ""
            ),
            "tk_ticks": self._lag_ticks,
            "capture_state": _safe(lambda: capture.state, "") if capture else "",
            "captured": _safe(lambda: capture.total_packets, "") if capture else "",
            "dropped": _safe(lambda: capture.dropped, "") if capture else "",
            "decode_errors": (
                _safe(lambda: capture.decode_errors, "") if capture else ""
            ),
            "sampled_out": _safe(lambda: capture.sampled_out, "") if capture else "",
            "persisted": _safe(lambda: capture.persisted_rows, "") if capture else "",
            "queue_depth": _safe(lambda: capture.queue_depth, "") if capture else "",
            "ui_buffer": (
                _safe(lambda: len(screen._buffer), "") if screen is not None else ""
            ),
            "ui_buffer_dropped": (
                _safe(lambda: screen._buffer_dropped, "") if screen is not None else ""
            ),
            "ui_rows": (
                _safe(lambda: screen._table.visible_count, "")
                if screen is not None
                else ""
            ),
            "rss_mb": system.get("rss_mb", ""),
            "threads": system.get("threads", ""),
            "tshark_children": system.get("tshark_children", ""),
            "db_ping_ms": system.get("db_ping_ms", ""),
        }
        try:
            self._handle.write(",".join(str(row[name]) for name in COLUMNS) + "\n")
            self._handle.flush()
        except OSError:
            pass

    def _traffic_screen(self) -> Any:
        """The live traffic screen, when it has been built and is current."""
        return _safe(
            lambda: self._root_window()._screens.get("traffic"), None  # noqa: SLF001
        )

    def _root_window(self) -> Any:
        return self._window

    #: Set by :func:`install` once the MainWindow exists.
    _window: Any = None

    # ------------------------------------------------------------------
    # Worker thread: everything that must not run on the Tk thread
    # ------------------------------------------------------------------
    def _sample_system(self) -> None:
        try:
            import psutil
        except ImportError:
            psutil = None  # type: ignore[assignment]
        process = psutil.Process() if psutil else None

        while not self._stop.wait(WINDOW_SECONDS):
            sample: dict[str, Any] = {}
            if process is not None:
                sample["rss_mb"] = _safe(
                    lambda: f"{process.memory_info().rss / 1048576:.1f}", ""
                )
                sample["threads"] = _safe(process.num_threads, "")
                sample["tshark_children"] = _safe(
                    lambda: sum(
                        1
                        for child in process.children(recursive=True)
                        if "shark" in (child.name() or "").lower()
                        or "dumpcap" in (child.name() or "").lower()
                    ),
                    "",
                )
            sample["db_ping_ms"] = self._ping_database()
            with self._lock:
                self._system = sample

    def _ping_database(self) -> str:
        """Round-trip time of the cheapest possible query.

        Off the Tk thread deliberately: if the database is what stalls the
        interface, measuring it on the Tk thread would add the stall to the
        very number meant to reveal it.
        """
        database = _safe(lambda: self._context.db, None)
        if database is None:
            return ""
        started = time.monotonic()
        ok = _safe(lambda: database.query_one("SELECT 1 AS ok"), None)
        if ok is None:
            return "ERR"
        return f"{(time.monotonic() - started) * 1000:.1f}"


def install(root: Any, context: Any, window: Any = None) -> FloodProbe | None:
    """Arm the probe when the environment asks for it, otherwise do nothing.

    Returns the probe so a caller can stop it, or ``None`` when the run is an
    ordinary one. Any failure to start is logged and swallowed: a diagnostic
    must not be the reason an application will not open.
    """
    if not enabled():
        return None
    try:
        log_dir = _safe(lambda: context.settings.log_dir, "logs")
        probe = FloodProbe(root, context, log_dir or "logs")
        probe._window = window
        probe.start()
        return probe
    except Exception:  # noqa: BLE001
        LOGGER.exception("Flood probe could not start; continuing without it.")
        return None
