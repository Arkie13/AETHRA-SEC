"""Hover tooltips (§60, §61).

A tooltip is how a dense operations console explains itself without filling the
screen with help text: the subsystem chips, table headings and metric tiles all
carry one. The text is supplied by the caller - usually a live status detail -
so a tooltip never asserts anything the application has not measured.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Callable

from aethra_sec.ui.theme import PALETTE

#: Delay before a tooltip appears, in milliseconds.
SHOW_DELAY_MS = 450


class Tooltip:
    """Attaches a hover tooltip to a widget.

    Args:
        widget: the widget to watch.
        text: static text, ignored when ``text_provider`` is given.
        text_provider: called each time the tooltip is about to appear, so a
            tooltip can show the current value rather than a stale one.
        wraplength: pixel width at which the text wraps.
    """

    def __init__(
        self,
        widget: tk.Misc,
        text: str = "",
        *,
        text_provider: Callable[[], str] | None = None,
        wraplength: int = 320,
        delay_ms: int = SHOW_DELAY_MS,
    ) -> None:
        """Bind the tooltip to the widget's enter/leave events."""
        self._widget = widget
        self._text = text
        self._provider = text_provider
        self._wraplength = wraplength
        self._delay = delay_ms
        self._window: tk.Toplevel | None = None
        self._after_id: str | None = None

        widget.bind("<Enter>", self._on_enter, add="+")
        widget.bind("<Leave>", self._on_leave, add="+")
        widget.bind("<ButtonPress>", self._on_leave, add="+")
        widget.bind("<Destroy>", self._on_leave, add="+")

    def set_text(self, text: str) -> None:
        """Replace the static text."""
        self._text = text

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------
    def _resolve_text(self) -> str:
        """Text to display, from the provider when one was supplied."""
        if self._provider is not None:
            try:
                return self._provider() or ""
            except Exception:  # noqa: BLE001 - a tooltip must never break a screen
                return ""
        return self._text

    def _on_enter(self, _event: tk.Event) -> None:
        """Schedule the tooltip."""
        self._cancel()
        self._after_id = self._widget.after(self._delay, self._show)

    def _on_leave(self, _event: tk.Event) -> None:
        """Cancel and hide."""
        self._cancel()
        self._hide()

    def _cancel(self) -> None:
        """Cancel a pending appearance."""
        if self._after_id is not None:
            try:
                self._widget.after_cancel(self._after_id)
            except tk.TclError:
                pass
            self._after_id = None

    def _show(self) -> None:
        """Create the tooltip window just below the widget."""
        self._after_id = None
        text = self._resolve_text()
        if not text or self._window is not None:
            return
        try:
            x = self._widget.winfo_rootx() + 12
            y = self._widget.winfo_rooty() + self._widget.winfo_height() + 6
        except tk.TclError:
            return

        window = tk.Toplevel(self._widget)
        window.wm_overrideredirect(True)
        window.configure(background=PALETTE.border_strong)
        frame = ttk.Frame(window, style="Toast.TFrame", padding=(10, 6))
        frame.pack(padx=1, pady=1)
        ttk.Label(
            frame, text=text, style="ToastBody.TLabel",
            wraplength=self._wraplength, justify="left",
        ).pack()
        window.wm_geometry(f"+{x}+{y}")
        try:
            window.wm_attributes("-topmost", True)
        except tk.TclError:  # pragma: no cover - platform dependent
            pass
        self._window = window

    def _hide(self) -> None:
        """Destroy the tooltip window."""
        if self._window is not None:
            try:
                self._window.destroy()
            except tk.TclError:
                pass
            self._window = None


def attach_tooltip(
    widget: tk.Misc,
    text: str = "",
    *,
    text_provider: Callable[[], str] | None = None,
    wraplength: int = 320,
) -> Tooltip:
    """Convenience wrapper returning the created :class:`Tooltip`."""
    return Tooltip(widget, text, text_provider=text_provider, wraplength=wraplength)


class CellTooltip:
    """One reusable hover box for individual cells of a table.

    :class:`Tooltip` explains a whole widget. A table needs the text to follow
    the cell under the pointer, so this keeps a single window and only
    rebuilds it when the pointer moves onto a different cell - moving within
    one cell does nothing, which is what stops it flickering. The text is
    computed by the caller from data it already holds; nothing here queries.

    Args:
        widget: the widget the cells belong to (a Treeview).
        delay_ms: how long the pointer must rest on a cell before it shows.
        wraplength: pixel width at which the text wraps.
    """

    def __init__(
        self,
        widget: tk.Misc,
        *,
        delay_ms: int = SHOW_DELAY_MS,
        wraplength: int = 460,
    ) -> None:
        self._widget = widget
        self._delay = delay_ms
        self._wraplength = wraplength
        self._window: tk.Toplevel | None = None
        self._label: ttk.Label | None = None
        self._after_id: str | None = None
        #: The cell currently shown or pending, as ``(item, column)``.
        self._cell: tuple[str, str] | None = None
        self._pending: tuple[str, int, int] | None = None

    @property
    def cell(self) -> tuple[str, str] | None:
        """The cell the box is showing or about to show."""
        return self._cell

    @property
    def text(self) -> str:
        """The text on screen, or empty when hidden."""
        if self._label is None or self._window is None:
            return ""
        try:
            return str(self._label.cget("text"))
        except tk.TclError:
            return ""

    def point_at(
        self, item: str, column: str, text: str, x_root: int, y_root: int
    ) -> None:
        """The pointer is over ``(item, column)``, whose details are ``text``.

        The same cell again is a no-op; a different cell replaces the text.
        Empty text hides the box - a cell with nothing honest to say shows
        nothing rather than an empty frame.
        """
        if not text:
            self.hide()
            return
        if self._cell == (item, column):
            return
        self._cancel()
        self._cell = (item, column)
        self._pending = (text, x_root, y_root)
        if self._window is not None:
            self._show()  # already visible: move straight to the new cell
            return
        try:
            self._after_id = self._widget.after(self._delay, self._show)
        except tk.TclError:  # pragma: no cover - widget closing
            self._after_id = None

    def hide(self) -> None:
        """Hide the box and forget the cell."""
        self._cancel()
        self._cell = None
        self._pending = None
        if self._window is not None:
            try:
                self._window.withdraw()
            except tk.TclError:
                self._window = None
                self._label = None

    def destroy(self) -> None:
        """Release the window for good."""
        self.hide()
        if self._window is not None:
            try:
                self._window.destroy()
            except tk.TclError:
                pass
        self._window = None
        self._label = None

    def _cancel(self) -> None:
        if self._after_id is not None:
            try:
                self._widget.after_cancel(self._after_id)
            except tk.TclError:
                pass
            self._after_id = None

    def _ensure_window(self) -> bool:
        if self._window is not None:
            return True
        try:
            window = tk.Toplevel(self._widget)
            window.wm_overrideredirect(True)
            window.configure(background=PALETTE.border_strong)
            frame = ttk.Frame(window, style="Toast.TFrame", padding=(12, 8))
            frame.pack(padx=1, pady=1)
            label = ttk.Label(
                frame, text="", style="ToastBody.TLabel",
                wraplength=self._wraplength, justify="left",
            )
            label.pack()
            try:
                window.wm_attributes("-topmost", True)
            except tk.TclError:  # pragma: no cover - platform dependent
                pass
            window.withdraw()
        except tk.TclError:  # pragma: no cover - widget closing
            return False
        self._window = window
        self._label = label
        return True

    def _show(self) -> None:
        self._after_id = None
        if self._pending is None or not self._ensure_window():
            return
        text, x_root, y_root = self._pending
        window, label = self._window, self._label
        assert window is not None and label is not None
        try:
            label.configure(text=text)
            window.update_idletasks()
            width, height = window.winfo_reqwidth(), window.winfo_reqheight()
            screen_w = window.winfo_screenwidth()
            screen_h = window.winfo_screenheight()
            # Beside the pointer, and kept on screen: flipped to the left or
            # above when it would run off the right or bottom edge.
            x = x_root + 16
            y = y_root + 18
            if x + width > screen_w:
                x = max(0, x_root - width - 12)
            if y + height > screen_h:
                y = max(0, y_root - height - 12)
            window.wm_geometry(f"+{x}+{y}")
            window.deiconify()
            window.lift()
        except tk.TclError:  # pragma: no cover - widget closing
            self._window = None
            self._label = None
