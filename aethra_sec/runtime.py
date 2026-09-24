"""Process-level hardening that a packaged build needs and a checkout does not.

Running from source, a Python process always has a console: ``sys.stdout`` and
``sys.stderr`` are real files, ``print`` works, and an exception that escapes a
Tkinter callback prints a traceback to the terminal and the application carries
on.

A windowed PyInstaller build has none of that. There is no console, so
``sys.stdout`` and ``sys.stderr`` are ``None``, and the consequences are worse
than losing the output:

* any ``print`` raises ``AttributeError: 'NoneType' object has no attribute
  'write'``;
* Tkinter's default ``report_callback_exception`` writes the traceback to
  ``sys.stderr`` - so an ordinary, recoverable error inside a callback raises a
  *second* exception inside the error handler itself, and that one is not
  caught. The window can disappear with nothing written anywhere, at whatever
  moment the first error happened to occur.

That second failure mode is the reason this module exists. It is the classic way
a packaged Tkinter application dies silently some time after starting, and the
"some time" is simply whenever the first callback error happens.

:func:`install` fixes both: it gives the process real streams to write to, and
replaces the Tk error handler with one that writes to the application log and
keeps the interface running. Neither changes behaviour when running from source
beyond routing Tk callback errors into the log, which is where they belong.
"""

from __future__ import annotations

import io
import sys
import traceback
from typing import Any

from aethra_sec.utils.logging import get_logger

LOGGER = get_logger("runtime")

#: Set once, so repeated calls are harmless.
_INSTALLED = False


class _LogStream(io.TextIOBase):
    """A writable stream that forwards whole lines to the application log.

    Stands in for ``sys.stdout``/``sys.stderr`` when the process has none.
    Anything a library prints therefore ends up in the log file instead of
    raising, which is both where an operator can find it and the reason the
    process stays alive.
    """

    def __init__(self, level: int) -> None:
        """Create a stream that logs at ``level``."""
        super().__init__()
        self._level = level
        self._buffer = ""

    def writable(self) -> bool:
        """Always true - this exists to be written to."""
        return True

    def write(self, text: str) -> int:
        """Buffer ``text`` and log each complete line."""
        if not text:
            return 0
        self._buffer += text
        while "\n" in self._buffer:
            line, _, self._buffer = self._buffer.partition("\n")
            if line.strip():
                LOGGER.log(self._level, "%s", line.rstrip())
        return len(text)

    def flush(self) -> None:
        """Log whatever is left without a trailing newline."""
        if self._buffer.strip():
            LOGGER.log(self._level, "%s", self._buffer.rstrip())
        self._buffer = ""


def ensure_streams() -> None:
    """Give the process usable ``stdout``/``stderr`` if it has none.

    Only replaces a stream that is actually missing. A console build, a
    redirected run and the test suite all keep the streams they were given.
    """
    import logging

    if sys.stdout is None:
        sys.stdout = _LogStream(logging.INFO)  # type: ignore[assignment]
    if sys.stderr is None:
        sys.stderr = _LogStream(logging.ERROR)  # type: ignore[assignment]
    # __stdout__/__stderr__ are what some libraries reach for directly.
    if getattr(sys, "__stdout__", None) is None:
        sys.__stdout__ = sys.stdout  # type: ignore[assignment]
    if getattr(sys, "__stderr__", None) is None:
        sys.__stderr__ = sys.stderr  # type: ignore[assignment]


def install_tk_exception_handler(root: Any) -> None:
    """Send Tk callback errors to the log instead of to a missing stderr.

    The default handler writes to ``sys.stderr``. With no console that write
    raises inside the handler, and the failure escapes as an unhandled error
    during event dispatch - which is how a packaged Tkinter application exits
    without a message. Logging instead keeps the interface running and leaves
    an operator something to read.

    A callback error is *not* treated as fatal. One screen failing to refresh
    must not take the console down with it; the log records what happened and
    the next event is dispatched normally.
    """

    def report(exc_type: type[BaseException], value: BaseException, tb: Any) -> None:
        text = "".join(traceback.format_exception(exc_type, value, tb))
        LOGGER.error("Unhandled error in a Tk callback:\n%s", text)

    try:
        root.report_callback_exception = report
    except Exception:  # noqa: BLE001 - never let hardening break startup
        LOGGER.debug("Could not install the Tk exception handler.", exc_info=True)


def install_thread_exception_handler() -> None:
    """Log exceptions that escape a worker thread rather than losing them.

    Python's default prints them to ``sys.stderr``. In a windowed build that is
    the same trap as the Tk handler, and a background worker dying quietly is
    exactly the failure the System Health screen is supposed to be able to
    report.
    """
    import threading

    def hook(args: Any) -> None:
        if args.exc_type is SystemExit:
            return
        text = "".join(
            traceback.format_exception(args.exc_type, args.exc_value, args.exc_traceback)
        )
        LOGGER.error(
            "Unhandled error in thread '%s':\n%s",
            getattr(args.thread, "name", "unknown"), text,
        )

    threading.excepthook = hook


def install_process_exception_handler() -> None:
    """Record any exception that would otherwise end the process silently."""
    previous = sys.excepthook

    def hook(exc_type: type[BaseException], value: BaseException, tb: Any) -> None:
        if issubclass(exc_type, KeyboardInterrupt):
            previous(exc_type, value, tb)
            return
        text = "".join(traceback.format_exception(exc_type, value, tb))
        LOGGER.critical("AETHRA-SEC is exiting on an unhandled error:\n%s", text)
        previous(exc_type, value, tb)

    sys.excepthook = hook


def install(root: Any = None) -> None:
    """Apply every hardening step. Safe to call more than once."""
    global _INSTALLED

    ensure_streams()
    if not _INSTALLED:
        install_thread_exception_handler()
        install_process_exception_handler()
        _INSTALLED = True
    if root is not None:
        install_tk_exception_handler(root)


def apply_window_icon(window: Any) -> bool:
    """Give a Tk window the AETHRA-SEC icon.

    Returns True when the icon was applied. A missing icon is reported rather
    than raised: an application that refused to open because a ``.ico`` had been
    quarantined by anti-virus would be a worse outcome than a default icon.
    """
    try:
        from aethra_sec.resources import APPLICATION_ICON, resolve

        icon = resolve(APPLICATION_ICON)
        if not icon.available:
            LOGGER.warning("Application icon unavailable: %s", icon.detail)
            return False
        window.iconbitmap(default=str(icon.path))
        return True
    except Exception:  # noqa: BLE001 - an icon must never stop the console
        LOGGER.debug("Could not apply the window icon.", exc_info=True)
        return False
