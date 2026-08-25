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
