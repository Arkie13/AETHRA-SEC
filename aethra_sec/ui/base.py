"""Screen base class shared by every AETHRA-SEC page.

Two responsibilities:

* give screens a uniform lifecycle (``on_show`` / ``on_hide`` / ``refresh``);
* give them a safe way to run slow work. :meth:`Screen.run_async` moves the
  work to a worker thread and hands the result back through
  :mod:`aethra_sec.ui.dispatch`, which runs it on the Tk thread. A worker never
  touches a widget itself - Tkinter forbids it, and Python 3.14 raises (§37,
  §105).
"""

from __future__ import annotations

import threading
import tkinter as tk
from tkinter import ttk
from typing import Any, Callable

from aethra_sec.core.application import ApplicationContext
from aethra_sec.core.errors import AethraError, user_facing
from aethra_sec.core.session import Session
from aethra_sec.ui import dispatch
from aethra_sec.ui.theme import Fonts
from aethra_sec.ui.widgets.dialogs import show_error
from aethra_sec.utils.logging import get_logger

LOGGER = get_logger("ui.screen")


class Screen(ttk.Frame):
    """Base class for every navigable page."""

    #: Title shown in the header.
    title = "Screen"
    #: Subtitle shown under the title.
    subtitle = ""
    #: Permission required to open the screen (empty means "any session").
    required_permission = ""

    def __init__(self, parent: tk.Misc, app: "MainWindowProtocol") -> None:
        """Create the screen bound to the running application."""
        super().__init__(parent, style="TFrame")
        self.app = app
        self.context: ApplicationContext = app.context
        self.fonts: Fonts = app.fonts
        self._destroyed = False
        #: Outstanding async jobs this screen started, so overlapping loads
        #: raise and clear the indicator once rather than fighting over it.
        self._busy_depth = 0
        self._loader: ttk.Progressbar | None = None
        self.bind("<Destroy>", self._on_destroy)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    @property
    def session(self) -> Session | None:
        """The signed-in session."""
        return self.context.current_session

    def build(self) -> None:
        """Create the screen's widgets. Called once, lazily, on first show."""

    def on_show(self) -> None:
        """Called each time the screen becomes visible."""
        self.refresh()

    def on_hide(self) -> None:
        """Called when the screen is navigated away from."""

    def refresh(self) -> None:
        """Reload the screen's data."""

    def on_tick(self) -> None:
        """Called on the UI refresh tick while this screen is visible."""

    def handle_event(self, event: Any) -> None:
        """Handle an event-bus event delivered on the Tk thread."""

    # ------------------------------------------------------------------
    # Threading helpers
    # ------------------------------------------------------------------
    def _on_destroy(self, event: tk.Event) -> None:
        """Record destruction so late callbacks become no-ops."""
        if event.widget is self:
            self._destroyed = True

    @property
    def is_alive(self) -> bool:
        """False once the screen has been destroyed."""
        return not self._destroyed and bool(self.winfo_exists())

    def run_async(
        self,
        work: Callable[[], Any],
        on_success: Callable[[Any], None] | None = None,
        on_error: Callable[[str], None] | None = None,
        *,
        name: str = "ui-worker",
    ) -> None:
        """Run ``work`` off the Tk thread and deliver the result back on it.

        This is how every screen performs database queries, exports and tool
        invocations without freezing the interface.
        """

        def deliver(callback: Callable[[Any], None], payload: Any) -> None:
            """Hand a worker's result back to the Tk thread.

            Touch no Tk call from here: this runs on the worker thread, and
            Tkinter forbids that - it raises "main thread is not in main loop".
            That bars ``after()`` and equally ``winfo_exists()``, so the cheap
            destroyed flag is all this side may read. The real liveness check
            runs inside the posted callable, on the Tk thread, where asking
            the widget is both safe and accurate.
            """
            if self._destroyed:
                return
            dispatch.post(lambda: callback(payload) if self.is_alive else None)

        def finish() -> None:
            """Clear the activity marker back on the Tk thread."""
            self.set_busy(False)

        def runner() -> None:
            try:
                result = work()
            except AethraError as exc:
                LOGGER.debug("Async work failed: %s", exc, exc_info=True)
                deliver(on_error or self.show_error_message, exc.user_message)
            except Exception as exc:  # noqa: BLE001
                LOGGER.exception("Async work failed unexpectedly.")
                deliver(on_error or self.show_error_message, user_facing(exc))
            else:
                if on_success is not None:
                    deliver(on_success, result)
            finally:
                deliver(lambda _payload: finish(), None)

        self.set_busy(True)
        threading.Thread(target=runner, name=name, daemon=True).start()

    def set_busy(self, busy: bool) -> None:
        """Show or clear the activity indication for work this screen started.

        Two signals, because they answer different questions: a marker in the
        status bar says *the console is doing something*, and a thin progress
        bar across the top of this screen says *this page is the one waiting*.
        Neither blocks input - a slow query must not freeze the interface.
        """
        self._busy_depth = max(0, self._busy_depth + (1 if busy else -1))
        marker = getattr(self.app, "_set_busy", None)
        if callable(marker):
            try:
                marker(busy)
            except tk.TclError:  # pragma: no cover - window closing
                pass
        self._paint_busy()

    def _paint_busy(self) -> None:
        """Show the loading bar while this screen has work in flight."""
        if not self.is_alive:
            return
        try:
            if self._busy_depth and self._loader is None:
                self._loader = ttk.Progressbar(self, mode="indeterminate", length=120)
                self._loader.place(relx=0, rely=0, relwidth=1, height=3)
                self._loader.lift()
                self._loader.start(14)
            elif not self._busy_depth and self._loader is not None:
                self._loader.stop()
                self._loader.destroy()
                self._loader = None
        except tk.TclError:  # pragma: no cover - window closing
            self._loader = None

    def show_error_message(self, message: str, title: str = "Operation failed") -> None:
        """Display an error dialog with the real, actionable message."""
        if self.is_alive:
            show_error(self, title, title, detail=message, fonts=self.fonts)

    def status(self, message: str) -> None:
        """Post a message to the main window's status bar (§108).

        Tolerates a destroyed window: a worker's result can arrive after the
        operator has signed out, and a late status update must not raise.
        """
        try:
            self.app.set_status(message)
        except tk.TclError:
            LOGGER.debug("Status update after window teardown: %s", message)

    def can(self, permission: str) -> bool:
        """True when the session holds a permission (used to gate controls)."""
        access = self.context.access
        if access is None:
            return False
        return access.has(self.session, permission)


class MainWindowProtocol:
    """Structural type for the main window a screen talks to.

    Declared explicitly rather than imported to avoid a circular import between
    the window and the screens it hosts.
    """

    context: ApplicationContext
    fonts: Fonts

    def set_status(self, message: str) -> None:
        """Show a message in the status bar."""
        raise NotImplementedError

    def navigate(self, screen_key: str, **kwargs: Any) -> None:
        """Switch to another screen."""
        raise NotImplementedError

    def refresh_notifications(self) -> None:
        """Refresh the notification badge."""
        raise NotImplementedError
