"""Hand results from worker threads back to the Tk thread (§75).

Tkinter is single-threaded. Calling ``widget.after()`` from a worker thread
happened to work on older interpreters, but it was never safe - it registers a
Tcl command from the wrong thread - and **Python 3.14 raises**::

    RuntimeError: main thread is not in main loop

So no worker in AETHRA-SEC touches Tk at all. A worker calls :func:`post`,
which puts the callable on a thread-safe queue; the Tk thread drains that queue
on a timer it started itself, and runs the callables in the order they arrived.

There is exactly one dispatcher per process, installed on the root window by
:func:`install` before any window is shown.
"""

from __future__ import annotations

import queue
import threading
import tkinter as tk
from typing import Callable

from aethra_sec.utils.logging import get_logger

LOGGER = get_logger("ui.dispatch")

#: How often the Tk thread drains the queue. Small enough to feel immediate,
#: large enough to cost nothing while idle.
DRAIN_INTERVAL_MS = 40

#: Most callables run per drain, so a burst cannot stall the interface.
MAX_PER_DRAIN = 200


class TkDispatcher:
    """Runs callables on the Tk main thread on behalf of worker threads."""

    def __init__(self, root: tk.Misc, interval_ms: int = DRAIN_INTERVAL_MS) -> None:
        """Bind the dispatcher to a root window (it does not start it)."""
        self._root = root
        self._interval = max(10, int(interval_ms))
        self._queue: queue.Queue[Callable[[], None]] = queue.Queue()
        self._job: str | None = None
        self._running = False

    # ------------------------------------------------------------------
    # Lifecycle - main thread only
    # ------------------------------------------------------------------
    def start(self) -> None:
        """Begin draining. Must be called from the Tk thread."""
        if self._running:
            return
        self._running = True
        self._schedule()

    def stop(self) -> None:
        """Stop draining and discard anything still queued."""
        self._running = False
        if self._job is not None:
            try:
                self._root.after_cancel(self._job)
            except (tk.TclError, ValueError):  # pragma: no cover - already gone
                pass
            self._job = None
        while True:
            try:
                self._queue.get_nowait()
            except queue.Empty:
                break

    @property
    def is_running(self) -> bool:
        """True while the drain timer is active."""
        return self._running

    @property
    def pending(self) -> int:
        """Callables waiting to run (used by the tests)."""
        return self._queue.qsize()

    # ------------------------------------------------------------------
    # Posting - any thread
    # ------------------------------------------------------------------
    def post(self, callback: Callable[[], None]) -> None:
        """Queue ``callback`` to run on the Tk thread.

        Safe from any thread. When called from the Tk thread itself the
        callable still goes through the queue, so ordering is the same however
        it was posted.
        """
        if not self._running:
            LOGGER.debug("Dispatcher is not running; dropping a queued callback.")
            return
        self._queue.put(callback)

    # ------------------------------------------------------------------
    # Draining - main thread only
    # ------------------------------------------------------------------
    def drain(self) -> int:
        """Run the queued callables. Returns how many ran."""
        executed = 0
        while executed < MAX_PER_DRAIN:
            try:
                callback = self._queue.get_nowait()
            except queue.Empty:
                break
            executed += 1
            try:
                callback()
            except tk.TclError:
                # The window went away between posting and draining.
                LOGGER.debug("Queued UI callback ran after teardown.", exc_info=True)
            except Exception:  # noqa: BLE001 - one bad callback must not stop the rest
                LOGGER.exception("A queued UI callback failed.")
        return executed

    def _schedule(self) -> None:
        """Queue the next drain."""
        if not self._running:
            return
        try:
            self._job = self._root.after(self._interval, self._tick)
        except tk.TclError:  # pragma: no cover - root destroyed
            self._running = False

    def _tick(self) -> None:
        """Drain, then schedule the next drain."""
        if not self._running:
            return
        self.drain()
        self._schedule()


#: The process-wide dispatcher, installed by :func:`install`.
_DISPATCHER: TkDispatcher | None = None


def install(root: tk.Misc) -> TkDispatcher:
    """Create and start the dispatcher for ``root``. Call from the Tk thread."""
    global _DISPATCHER
    if _DISPATCHER is not None:
        _DISPATCHER.stop()
    _DISPATCHER = TkDispatcher(root)
    _DISPATCHER.start()
    return _DISPATCHER


def ensure(root: tk.Misc) -> TkDispatcher:
    """Return the running dispatcher, installing one for ``root`` if needed.

    Every window that starts background work calls this in its constructor, so
    a window built directly - by a test, or by embedding code - can never end
    up with workers whose results have nowhere to go.
    """
    if _DISPATCHER is not None and _DISPATCHER.is_running:
        return _DISPATCHER
    return install(root)


def shutdown() -> None:
    """Stop the dispatcher, if one is installed."""
    global _DISPATCHER
    if _DISPATCHER is not None:
        _DISPATCHER.stop()
        _DISPATCHER = None


def current() -> TkDispatcher | None:
    """The installed dispatcher, if any."""
    return _DISPATCHER


def post(callback: Callable[[], None]) -> bool:
    """Run ``callback`` on the Tk thread from wherever you are.

    Returns:
        True when the callable was queued or run. False when there is no
        dispatcher and the caller is not on the main thread, which means the
        result cannot be delivered safely and must be dropped rather than risk
        touching Tk from a worker.
    """
    dispatcher = _DISPATCHER
    if dispatcher is not None and dispatcher.is_running:
        dispatcher.post(callback)
        return True

    if threading.current_thread() is threading.main_thread():
        # No dispatcher (a unit test, or teardown) but we are already on the
        # right thread, so running inline is safe.
        try:
            callback()
        except tk.TclError:  # pragma: no cover - window closing
            return False
        return True

    LOGGER.debug("No UI dispatcher is running; a worker result was dropped.")
    return False
