"""Transient toast notifications (§52, §108).

A toast is raised only by a real event that the application observed - a scan
finishing, a capture failing, an incident being correlated. Nothing schedules a
decorative toast, and a toast never reports a state the subsystem did not
report itself.

Toasts stack above the status bar in the bottom-right corner of the console,
newest at the bottom, and dismiss themselves after a few seconds. Clicking one
runs its action (usually: open the screen that owns the event).
"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Callable

from aethra_sec.ui.theme import PALETTE, Fonts

#: How long a toast stays on screen, by level.
DURATION_MS: dict[str, int] = {
    "INFO": 5000,
    "SUCCESS": 5000,
    "WARNING": 8000,
    "CRITICAL": 12000,
}

#: Accent colour per level.
LEVEL_COLOURS: dict[str, str] = {
    "INFO": PALETTE.info,
    "SUCCESS": PALETTE.ok,
    "WARNING": PALETTE.medium,
    "CRITICAL": PALETTE.critical,
}

#: Most toasts on screen at once; older ones are dismissed to make room.
MAX_VISIBLE = 4


class ToastManager:
    """Owns the toast stack for one window."""

    def __init__(self, host: tk.Misc, fonts: Fonts) -> None:
        """Bind the manager to the frame toasts are placed in."""
        self._host = host
        self._fonts = fonts
        self._toasts: list[ttk.Frame] = []

    def show(
        self,
        title: str,
        message: str = "",
        *,
        level: str = "INFO",
        on_click: Callable[[], None] | None = None,
    ) -> None:
        """Raise a toast for a real event."""
        level = (level or "INFO").upper()
        colour = LEVEL_COLOURS.get(level, PALETTE.info)

        while len(self._toasts) >= MAX_VISIBLE:
            self._dismiss(self._toasts[0])

        try:
            frame = ttk.Frame(self._host, style="Toast.TFrame", padding=(0, 0))
        except tk.TclError:  # pragma: no cover - window is closing
            return

        accent = tk.Frame(frame, background=colour, width=3)
        accent.pack(side="left", fill="y")

        body = ttk.Frame(frame, style="Toast.TFrame", padding=(12, 9))
        body.pack(side="left", fill="both", expand=True)

        heading = ttk.Frame(body, style="Toast.TFrame")
        heading.pack(fill="x")
        title_label = ttk.Label(heading, text=title, style="Toast.TLabel")
        title_label.configure(foreground=colour)
        title_label.pack(side="left")
        close = ttk.Label(heading, text="✕", style="ToastBody.TLabel", cursor="hand2")
        close.pack(side="right", padx=(10, 0))
        close.bind("<Button-1>", lambda _event: self._dismiss(frame))

        message_label: ttk.Label | None = None
        if message:
            message_label = ttk.Label(
                body, text=message, style="ToastBody.TLabel",
                wraplength=330, justify="left",
            )
            message_label.pack(anchor="w", pady=(3, 0))

        if on_click is not None:
            for widget in (frame, body, heading, title_label, message_label):
                if widget is None:
                    continue
                widget.configure(cursor="hand2")
                widget.bind(
                    "<Button-1>",
                    lambda _event, action=on_click, target=frame: (
                        self._dismiss(target), action()
                    ),
                )

        self._toasts.append(frame)
        self._relayout()
        self._host.after(DURATION_MS.get(level, 5000), lambda: self._dismiss(frame))

    def clear(self) -> None:
        """Dismiss every toast (used on shutdown)."""
        for frame in list(self._toasts):
            self._dismiss(frame)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------
    def _dismiss(self, frame: ttk.Frame) -> None:
        """Remove one toast."""
        if frame not in self._toasts:
            return
        self._toasts.remove(frame)
        try:
            frame.destroy()
        except tk.TclError:
            pass
        self._relayout()

    def _relayout(self) -> None:
        """Stack the toasts from the bottom-right corner upwards."""
        offset = 0
        for frame in reversed(self._toasts):
            try:
                frame.place(relx=1.0, rely=1.0, anchor="se", x=-18, y=-18 - offset)
                frame.update_idletasks()
                offset += frame.winfo_reqheight() + 10
            except tk.TclError:  # pragma: no cover - window is closing
                return
