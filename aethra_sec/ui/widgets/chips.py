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
from tkinter import ttk
from typing import Any, Callable

from aethra_sec.ui.theme import (
    PALETTE,
    Fonts,
    chip_colours,
    is_active_state,
    motion_enabled,
    pulse_colour,
    severity_colour,
    state_colour,
    status_colour,
    text_on,
)
from aethra_sec.ui.widgets.tooltip import Tooltip

#: Interval between pulse frames on an active status dot. Slow enough to read
#: as a calm breathe rather than a blink, cheap enough to cost nothing.
PULSE_MS = 130


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
        colour: str = "",
        fonts: Fonts | None = None,
        surface: str = "",
        dot: bool = False,
        on_click: Callable[[], None] | None = None,
        tooltip: str = "",
        tooltip_provider: Callable[[], str] | None = None,
        height: int = 22,
        min_width: int = 0,
        compact: bool = False,
    ) -> None:
        """Create the chip.

        ``compact`` drops the tinted pill and draws only the dot and its
        label. Five subsystem pills needed a header row of their own; as
        compact indicators they fit on the command bar beside the search,
        which is where a status belongs - always visible, never a section.
        """
        self._compact = compact
        self._surface = surface or PALETTE.surface
        super().__init__(
            parent, height=height, background=self._surface,
            highlightthickness=0, borderwidth=0,
        )
        self._fonts = fonts
        self._font = fonts.small_bold if fonts else ("TkDefaultFont", 8, "bold")
        self._text = text
        self._colour = colour or PALETTE.accent
        self._dot = dot
        self._height = height
        self._min_width = min_width
        self._on_click = on_click
        self._hovering = False
        #: Active-state pulse: only the dot animates, only for a live state,
        #: and only when motion is enabled. Everything else is drawn static.
        self._pulse_active = False
        self._pulse_phase = 1.0
        self._pulse_dir = -1.0
        self._pulse_job: str | None = None
        self._dot_item: int | None = None
        #: Built on first use and kept; see :meth:`_measure`.
        self._measurer: Any = None

        if on_click is not None:
            self.configure(cursor="hand2")
            self.bind("<Button-1>", lambda _event: on_click())
        self.bind("<Enter>", self._on_enter)
        self.bind("<Leave>", self._on_leave)
        self.bind("<Configure>", lambda _event: self._redraw())
        self.bind("<Destroy>", self._on_destroy)

        self._tooltip: Tooltip | None = None
        if tooltip or tooltip_provider is not None:
            self._tooltip = Tooltip(self, tooltip, text_provider=tooltip_provider)

        self._measure()
        self._redraw()

    # ------------------------------------------------------------------
    # Content
    # ------------------------------------------------------------------
    def set_value(self, text: str, colour: str | None = None) -> None:
        """Update the label and, optionally, the accent colour.

        Returns immediately when neither has changed. The header repaints the
        whole status strip on every UI tick so it is correct even before the
        first status change is published, which means almost every call asks
        for the chip it is already showing. Measured with capture running, that
        unconditional repaint cost 441-568 ms of the Tk thread per tick, worst
        1,271 ms - the application froze for a second or more, recovered, and
        froze again on the next tick. Redrawing only on a real change costs
        nothing when nothing changed.
        """
        if text == self._text and (not colour or colour == self._colour):
            return
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
        """Size the canvas to fit the text.

        The measuring font is built once and kept. It used to be constructed
        on every call, and each construction allocates a Tcl font command that
        Tk must later reclaim - paid once per chip per repaint, on the Tk
        thread. Caching it is free: the font never changes for the life of the
        widget, because a theme change rebuilds the chip.
        """
        try:
            measurer = self._measurer
            if measurer is None:
                from tkinter import font as tkfont

                measurer = self._measurer = tkfont.Font(root=self, font=self._font)
            width = measurer.measure(self._text or "")
        except Exception:  # noqa: BLE001 - font measurement is best effort
            width = 8 * len(self._text or "")
        # A compact indicator has no pill, so it needs only the dot's width
        # and a small trailing gap rather than a pill's horizontal padding.
        if self._compact:
            padding = 16 + (12 if self._dot else 0)
        else:
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

    # ------------------------------------------------------------------
    # Active-state pulse
    # ------------------------------------------------------------------
    def set_pulsing(self, active: bool) -> None:
        """Pulse the dot while ``active`` is true (only if it has a dot)."""
        active = bool(active) and self._dot
        if active == self._pulse_active:
            return
        self._pulse_active = active
        if active:
            if self._pulse_job is None and motion_enabled():
                self._pulse_tick()
        else:
            self._stop_pulse()
            self._pulse_phase = 1.0
            if self._dot_item is not None:
                try:
                    self.itemconfigure(self._dot_item, fill=self._colour)
                except tk.TclError:  # pragma: no cover - torn down
                    pass

    def _pulse_tick(self) -> None:
        """Advance the breathe by one frame; stop cleanly when it should."""
        self._pulse_job = None
        if not self._pulse_active or not self.winfo_exists():
            return
        if not motion_enabled():
            # Reduced motion turned on mid-pulse: settle solid and stop.
            self._pulse_phase = 1.0
            if self._dot_item is not None:
                try:
                    self.itemconfigure(self._dot_item, fill=self._colour)
                except tk.TclError:  # pragma: no cover
                    pass
            return
        self._pulse_phase += self._pulse_dir * 0.18
        if self._pulse_phase <= 0.25:
            self._pulse_phase, self._pulse_dir = 0.25, 1.0
        elif self._pulse_phase >= 1.0:
            self._pulse_phase, self._pulse_dir = 1.0, -1.0
        if self._dot_item is not None:
            try:
                self.itemconfigure(
                    self._dot_item, fill=pulse_colour(self._colour, self._pulse_phase)
                )
            except tk.TclError:  # pragma: no cover - torn down
                return
        self._pulse_job = self.after(PULSE_MS, self._pulse_tick)

    def _stop_pulse(self) -> None:
        """Cancel the pulse timer if one is armed."""
        if self._pulse_job is not None:
            try:
                self.after_cancel(self._pulse_job)
            except (tk.TclError, ValueError):  # pragma: no cover
                pass
            self._pulse_job = None

    def _on_destroy(self, event: tk.Event) -> None:
        """Stop the pulse when the chip goes away."""
        if event.widget is self:
            self._stop_pulse()

    def _redraw(self) -> None:
        """Repaint the chip."""
        self.delete("all")
        width = max(int(self.winfo_width()), int(self["width"]))
        height = max(int(self.winfo_height()), self._height)
        foreground, background = chip_colours(self._colour, surface=self._surface)
        if self._hovering:
            _, background = chip_colours(self._colour, surface=PALETTE.surface_hover)

        if not self._compact:
            rounded_rectangle(
                self, 1, 1, width - 1, height - 1, radius=height / 2,
                fill=background, outline="",
            )
        text_x = 12 if not self._compact else 10
        if self._dot:
            centre = height / 2
            left = 10 if not self._compact else 2
            dot_fill = (
                pulse_colour(self._colour, self._pulse_phase)
                if self._pulse_active and motion_enabled()
                else self._colour
            )
            self._dot_item = self.create_oval(
                left, centre - 3, left + 6, centre + 3,
                fill=dot_fill, outline="",
            )
            text_x = 22 if not self._compact else 12
        if self._compact:
            # No pill, so the label carries the state colour itself.
            foreground = self._colour
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
        compact: bool = False,
    ) -> None:
        """Create the chip in its unknown state."""
        self._label = label
        super().__init__(
            parent, f"{label} {state}", colour=state_colour(state), fonts=fonts,
            surface=surface, dot=True, on_click=on_click,
            tooltip_provider=tooltip_provider, compact=compact,
        )

    def set_text(self, text: str, *, colour: str = "") -> None:
        """Replace the label and colour without changing the bound state.

        Guarded like :meth:`set_value`: this is the call the header's status
        strip makes for every chip on every UI tick, so it is almost always
        asked for what the chip already shows.
        """
        if text == self._text and (not colour or colour == self._colour):
            return
        self._text = text
        if colour:
            self._colour = colour
        self._measure()
        self._redraw()

    def update_state(self, state: str) -> None:
        """Show a real probe result, pulsing the dot only for a live state."""
        self.set_value(f"{self._label} {state}", state_colour(state))
        self.set_pulsing(is_active_state(state))


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
        colour: str = "",
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
        self._colour = colour or PALETTE.accent
        self._size = size
        self._font = fonts.small_bold if fonts else ("TkDefaultFont", 8, "bold")
        #: -1 means "never painted", so the first set_count always draws -
        #: including the first zero, which is what hides the badge.
        self._count = -1
        #: Built on first use and kept; constructing a font per paint
        #: allocates a Tcl command each time.
        self._measurer: Any = None

    @property
    def count(self) -> int:
        """The count currently displayed."""
        return self._count

    def set_surface(self, surface: str) -> None:
        """Repaint the badge's ground so it matches the row beneath it.

        A sidebar entry changes ground when it becomes the current page, and a
        badge that kept the old one would show as a square patch on the band.
        """
        if surface == self._surface:
            return
        self._surface = surface
        try:
            self.configure(background=surface)
        except tk.TclError:  # pragma: no cover - torn down
            return
        self.set_count(self._count, colour=self._colour, force=True)

    def set_count(
        self, count: int, colour: str | None = None, *, force: bool = False
    ) -> None:
        """Show a count, hiding the badge when it is zero.

        Returns immediately when the count and colour are unchanged. The
        sidebar badges are refreshed on every UI tick, so this is nearly
        always asked for the number already on screen; repainting it anyway
        cost 305 ms of the Tk thread per tick with capture running.
        """
        count = max(0, int(count))
        if (
            not force
            and count == self._count
            and (not colour or colour == self._colour)
        ):
            return
        self._count = count
        if colour:
            self._colour = colour
        self.delete("all")
        if self._count == 0:
            self.configure(width=1)
            return

        text = "99+" if self._count > 99 else str(self._count)
        try:
            measurer = self._measurer
            if measurer is None:
                from tkinter import font as tkfont

                measurer = self._measurer = tkfont.Font(root=self, font=self._font)
            text_width = measurer.measure(text)
        except Exception:  # noqa: BLE001
            text_width = 8 * len(text)
        width = max(self._size, text_width + 12)
        self.configure(width=width, height=self._size)
        rounded_rectangle(
            self, 0, 1, width, self._size - 1, radius=(self._size - 2) / 2,
            fill=self._colour, outline="",
        )
        self.create_text(
            width / 2, self._size / 2, text=text, fill=text_on(self._colour), font=self._font
        )


class StatusRail(ttk.Frame):
    """Subsystem indicators that adapt to the width they are given.

    Five indicators reading ``DB CONNECTED``, ``NMAP AVAILABLE`` and so on
    need about 714px. The command bar has between 265px (1280 wide) and 525px
    (1920 wide) once the brand, search, clock and account controls have taken
    their share, so a fixed rail is clipped at *every* supported resolution -
    the last indicators are simply never placed, and a subsystem that is down
    becomes invisible rather than alarming.

    So the rail measures itself against the space it actually has and picks
    the densest form that fits:

    ``full``    dot + name + state       - what the design calls for
    ``label``   dot + name               - state carried by the dot's colour
    ``dot``     dot only                 - name carried by the tooltip

    Every form keeps all five indicators and their tooltips. Nothing is ever
    dropped, because a hidden subsystem state is worse than a terse one.
    """

    #: Gap between indicators, in each mode.
    GAP = 10

    def __init__(
        self,
        parent: tk.Misc,
        *,
        fonts: Fonts | None = None,
        surface: str = "",
        on_click: Callable[[], None] | None = None,
    ) -> None:
        """Create an empty rail; add indicators with :meth:`add`."""
        super().__init__(parent, style="Header.TFrame")
        self._fonts = fonts
        self._surface = surface or PALETTE.surface_alt
        self._on_click = on_click
        self._chips: dict[str, StatusChip] = {}
        self._labels: dict[str, str] = {}
        self._states: dict[str, str] = {}
        self._mode = ""
        self.bind("<Configure>", self._on_configure)

    def add(
        self, key: str, label: str, *, tooltip_provider: Callable[[], str] | None = None
    ) -> StatusChip:
        """Add one subsystem indicator."""
        chip = StatusChip(
            self, label, fonts=self._fonts, surface=self._surface, compact=True,
            on_click=self._on_click, tooltip_provider=tooltip_provider,
        )
        chip.pack(side="left", padx=(0, self.GAP))
        self._chips[key] = chip
        self._labels[key] = label
        self._states[key] = "UNKNOWN"
        return chip

    def update_state(self, key: str, state: str) -> None:
        """Record a real probe result and repaint that indicator."""
        if key not in self._chips:
            return
        self._states[key] = state
        self._apply(key)

    def _apply(self, key: str) -> None:
        """Render one indicator in the rail's current mode."""
        chip = self._chips[key]
        label, state = self._labels[key], self._states[key]
        if self._mode == "dot":
            chip.set_text("", colour=state_colour(state))
        elif self._mode == "label":
            chip.set_text(label, colour=state_colour(state))
        else:
            chip.set_text(f"{label} {state}", colour=state_colour(state))
        # The dot breathes only while the subsystem is genuinely active, so a
        # glance at the header distinguishes "running" from "stopped" by motion.
        chip.set_pulsing(is_active_state(state))

    def _width_for(self, mode: str) -> int:
        """Pixels the rail needs in a given mode."""
        try:
            from tkinter import font as tkfont

            measure = tkfont.Font(
                font=self._fonts.small_bold if self._fonts else None
            ).measure
        except Exception:  # noqa: BLE001 - measurement is best effort
            measure = lambda text: 8 * len(text)  # noqa: E731

        total = 0
        for key, label in self._labels.items():
            if mode == "dot":
                text = ""
            elif mode == "label":
                text = label
            else:
                text = f"{label} {self._states[key]}"
            total += measure(text) + 16 + 12 + self.GAP
        return total

    def _on_configure(self, event: tk.Event) -> None:
        """Choose the densest form that fits the width actually available."""
        available = int(event.width)
        if available <= 1:
            return
        for mode in ("full", "label", "dot"):
            if self._width_for(mode) <= available or mode == "dot":
                if mode != self._mode:
                    self._mode = mode
                    for key in self._chips:
                        self._apply(key)
                return
