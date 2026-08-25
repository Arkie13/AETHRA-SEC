"""Rounded status chips and count badges drawn on a Canvas (§10, §60).

ttk cannot draw a rounded, tinted pill, so these are drawn directly: a rounded
rectangle, an optional status dot, and a label. They are used for the header
subsystem strip, severity badges and sidebar counters.

A chip never invents a state. :class:`StatusChip` shows exactly the state string
its probe returned, and its dot is green only for a state the theme maps to
"healthy" - an unknown state stays grey.
"""

from __future__ import annotations

import tkinter as tk
from typing import Callable

from aethra_sec.ui.theme import (
    PALETTE,
    Fonts,
    chip_colours,
    severity_colour,
    state_colour,
    status_colour,
)
from aethra_sec.ui.widgets.tooltip import Tooltip


def rounded_rectangle(
    canvas: tk.Canvas,
    x1: float,
    y1: float,
    x2: float,
    y2: float,
    radius: float,
    **kwargs: object,
) -> int:
    """Draw a rounded rectangle and return its item id."""
    radius = max(0.0, min(radius, (x2 - x1) / 2, (y2 - y1) / 2))
    points = [
        x1 + radius, y1,
        x2 - radius, y1,
        x2, y1,
        x2, y1 + radius,
        x2, y2 - radius,
        x2, y2,
        x2 - radius, y2,
        x1 + radius, y2,
        x1, y2,
        x1, y2 - radius,
        x1, y1 + radius,
        x1, y1,
    ]
    return canvas.create_polygon(points, smooth=True, **kwargs)  # type: ignore[arg-type]


class Chip(tk.Canvas):
    """A tinted pill with optional leading dot, sized to its text."""

    def __init__(
        self,
        parent: tk.Misc,
        text: str = "",
        *,
        colour: str = PALETTE.accent,
        fonts: Fonts | None = None,
        surface: str = "",
        dot: bool = False,
        on_click: Callable[[], None] | None = None,
        tooltip: str = "",
        tooltip_provider: Callable[[], str] | None = None,
        height: int = 22,
        min_width: int = 0,
    ) -> None:
        """Create the chip."""
        self._surface = surface or PALETTE.surface
        super().__init__(
            parent, height=height, background=self._surface,
            highlightthickness=0, borderwidth=0,
        )
        self._fonts = fonts
        self._font = fonts.small_bold if fonts else ("TkDefaultFont", 8, "bold")
        self._text = text
        self._colour = colour
        self._dot = dot
        self._height = height
        self._min_width = min_width
        self._on_click = on_click
        self._hovering = False

        if on_click is not None:
            self.configure(cursor="hand2")
            self.bind("<Button-1>", lambda _event: on_click())
        self.bind("<Enter>", self._on_enter)
        self.bind("<Leave>", self._on_leave)
        self.bind("<Configure>", lambda _event: self._redraw())

        self._tooltip: Tooltip | None = None
        if tooltip or tooltip_provider is not None:
            self._tooltip = Tooltip(self, tooltip, text_provider=tooltip_provider)

        self._measure()
        self._redraw()

    # ------------------------------------------------------------------
    # Content
    # ------------------------------------------------------------------
    def set_value(self, text: str, colour: str | None = None) -> None:
        """Update the label and, optionally, the accent colour."""
        self._text = text
        if colour:
            self._colour = colour
        self._measure()
        self._redraw()

    def set_tooltip(self, text: str) -> None:
        """Replace the tooltip text."""
        if self._tooltip is not None:
            self._tooltip.set_text(text)

    def _measure(self) -> None:
        """Size the canvas to fit the text."""
        try:
            from tkinter import font as tkfont

            width = tkfont.Font(font=self._font).measure(self._text or "")
        except Exception:  # noqa: BLE001 - font measurement is best effort
            width = 8 * len(self._text or "")
        padding = 24 + (14 if self._dot else 0)
        self.configure(width=max(self._min_width, width + padding), height=self._height)

    def _on_enter(self, _event: tk.Event) -> None:
        """Lighten the chip while hovered when it is clickable."""
        self._hovering = self._on_click is not None
        self._redraw()

    def _on_leave(self, _event: tk.Event) -> None:
        """Restore the resting appearance."""
        self._hovering = False
        self._redraw()

    def _redraw(self) -> None:
        """Repaint the chip."""
        self.delete("all")
        width = max(int(self.winfo_width()), int(self["width"]))
        height = max(int(self.winfo_height()), self._height)
        foreground, background = chip_colours(self._colour, surface=self._surface)
        if self._hovering:
            _, background = chip_colours(self._colour, surface=PALETTE.surface_hover)

        rounded_rectangle(
            self, 1, 1, width - 1, height - 1, radius=height / 2,
            fill=background, outline="",
        )
        text_x = 12
        if self._dot:
            centre = height / 2
            self.create_oval(
                10, centre - 3, 16, centre + 3, fill=self._colour, outline=""
            )
            text_x = 22
        self.create_text(
            text_x, height / 2, text=self._text, anchor="w",
            fill=foreground, font=self._font,
        )


class StatusChip(Chip):
    """A chip bound to a subsystem state (``CONNECTED``, ``STOPPED``, ...)."""

    def __init__(
        self,
        parent: tk.Misc,
        label: str,
        *,
        state: str = "UNKNOWN",
        fonts: Fonts | None = None,
        surface: str = "",
        on_click: Callable[[], None] | None = None,
        tooltip_provider: Callable[[], str] | None = None,
    ) -> None:
        """Create the chip in its unknown state."""
        self._label = label
        super().__init__(
            parent, f"{label} {state}", colour=state_colour(state), fonts=fonts,
            surface=surface, dot=True, on_click=on_click,
            tooltip_provider=tooltip_provider,
        )

    def update_state(self, state: str) -> None:
        """Show a real probe result."""
        self.set_value(f"{self._label} {state}", state_colour(state))


class SeverityChip(Chip):
    """A chip bound to a severity, risk level or workflow status."""

    def __init__(
        self,
        parent: tk.Misc,
        value: str = "",
        *,
        kind: str = "severity",
        fonts: Fonts | None = None,
        surface: str = "",
    ) -> None:
        """Create the chip."""
        self._kind = kind
        super().__init__(
            parent, str(value), colour=self._colour_for(value), fonts=fonts,
            surface=surface,
        )

    def _colour_for(self, value: object) -> str:
        """Resolve the colour for this chip's kind."""
        return {
            "severity": severity_colour,
            "state": state_colour,
            "status": status_colour,
        }.get(self._kind, severity_colour)(value)

    def update_value(self, value: str) -> None:
        """Recolour for a new value."""
        self.set_value(str(value), self._colour_for(value))


class CountBadge(tk.Canvas):
    """A small count bubble, used on sidebar entries and the bell.

    A zero count hides the badge rather than drawing "0": the badge means
    "there is something here", and an empty system should look empty (§72).
    """

    def __init__(
        self,
        parent: tk.Misc,
        *,
        colour: str = PALETTE.accent,
        surface: str = "",
        fonts: Fonts | None = None,
        size: int = 18,
    ) -> None:
        """Create the badge, initially hidden."""
        self._surface = surface or PALETTE.surface
        super().__init__(
            parent, width=size, height=size, background=self._surface,
            highlightthickness=0, borderwidth=0,
        )
        self._colour = colour
        self._size = size
        self._font = fonts.small_bold if fonts else ("TkDefaultFont", 8, "bold")
        self._count = 0

    @property
    def count(self) -> int:
        """The count currently displayed."""
        return self._count

    def set_count(self, count: int, colour: str | None = None) -> None:
        """Show a count, hiding the badge when it is zero."""
        self._count = max(0, int(count))
        if colour:
            self._colour = colour
        self.delete("all")
        if self._count == 0:
            self.configure(width=1)
            return

        text = "99+" if self._count > 99 else str(self._count)
        try:
            from tkinter import font as tkfont

            text_width = tkfont.Font(font=self._font).measure(text)
        except Exception:  # noqa: BLE001
            text_width = 8 * len(text)
        width = max(self._size, text_width + 12)
        self.configure(width=width, height=self._size)
        rounded_rectangle(
            self, 0, 1, width, self._size - 1, radius=(self._size - 2) / 2,
            fill=self._colour, outline="",
        )
        self.create_text(
            width / 2, self._size / 2, text=text, fill="#FFFFFF", font=self._font
        )
