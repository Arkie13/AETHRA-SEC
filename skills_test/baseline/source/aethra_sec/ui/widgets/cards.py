"""Reusable card, indicator and empty-state widgets (§60, §72).

:class:`EmptyState` is not decoration - it is how AETHRA-SEC tells the truth
when there is nothing to show. Every list, chart and table in the application
renders one instead of inventing content.
"""

from __future__ import annotations

import tkinter as tk
from dataclasses import dataclass
from tkinter import ttk
from typing import Any, Callable, Sequence

from aethra_sec.ui.theme import (
    PALETTE,
    Fonts,
    motion_enabled,
    severity_colour,
    state_colour,
    status_colour,
)
from aethra_sec.ui.widgets.chips import rounded_rectangle
from aethra_sec.ui.widgets.surface import blend as _blend
from aethra_sec.ui.widgets.tooltip import attach_tooltip


class Card(tk.Canvas):
    """A rounded, elevated panel with a titled header.

    ttk cannot draw a radius, so for as long as this was a ``ttk.Frame`` every
    panel in the console was a hard-edged box with a hairline border, and no
    palette could change what that reads as. It is a Canvas now: the rounded
    body and its lit top edge are painted as canvas items, and the content sits
    on top of them.

    The construction API is unchanged. Screens still write ``Card(parent,
    "Title")`` and still parent their widgets to the card, because a Canvas is
    a perfectly ordinary geometry container - the only difference is that
    children are moved into a padded body frame once they arrive, which is what
    keeps them off the rounded corners.
    """

    #: Corner radius, matching the metric tiles so panels read as one family.
    RADIUS = 14

    def __init__(
        self,
        parent: tk.Misc,
        title: str = "",
        *,
        subtitle: str = "",
        padding: int = 0,
        fonts: Fonts | None = None,
        accent: str = "",
        page: str = "",
    ) -> None:
        """Create a card with an optional header."""
        self._page = page or PALETTE.background
        # A section takes the page colour: it is a grouping, not an object.
        self._fill = self._page
        super().__init__(
            parent, background=self._page, highlightthickness=0, borderwidth=0,
        )
        self.fonts = fonts
        self.header: ttk.Frame | None = None
        self.title_label: ttk.Label | None = None
        self.subtitle_label: ttk.Label | None = None
        self._accent = accent or PALETTE.accent
        self._drawn: tuple[int, int] = (-1, -1)

        self.body = ttk.Frame(self, style="Card.TFrame", padding=padding)
        self.body.pack(fill="both", expand=True)

        if title:
            self.header = ttk.Frame(self.body, style="Card.TFrame")
            self.header.pack(fill="x", pady=(0, 10))
            tk.Frame(self.header, background=self._accent, width=2, height=11).pack(
                side="left", padx=(0, 8)
            )
            self.title_label = ttk.Label(
                self.header, text=title.upper(), style="CardTitle.TLabel"
            )
            self.title_label.pack(side="left")
            if subtitle:
                self.subtitle_label = ttk.Label(
                    self.header, text=subtitle, style="CardDim.TLabel"
                )
                self.subtitle_label.pack(side="right")

        self.bind("<Configure>", self._on_configure)

    # ------------------------------------------------------------------
    def _on_configure(self, event: tk.Event) -> None:
        """Repaint the surface and take in any newly added children."""
        self._adopt()
        self._redraw(int(event.width), int(event.height))
        # The header's own geometry is not settled during this event, so the
        # rule is drawn again once the layout pass has actually run.
        if self.header is not None:
            self.after_idle(self._draw_rule)

    def _draw_rule(self) -> None:
        """Draw the header rule from settled geometry."""
        try:
            width = int(self.winfo_width())
        except tk.TclError:  # pragma: no cover - torn down
            return
        if width <= 2:
            return
        y = self._rule_y()
        self.delete("rule")
        if y > 0:
            self.create_line(0, y, width - 1, y, fill=PALETTE.border, tags="rule")
            self.tag_lower("rule")

    def _adopt(self) -> None:
        """Move children the screen parented to the card into its body.

        A widget built with the card as its parent is a child of the Canvas,
        so it would sit on the rounded corners with no padding. Re-packing it
        into the body frame - keeping the options the screen chose - puts it
        where the screen meant it to be without any call site changing.
        """
        for slave in self.pack_slaves():
            if slave is self.body:
                continue
            info = slave.pack_info()
            info.pop("in", None)
            try:
                slave.pack(in_=self.body, **info)
            except tk.TclError:  # pragma: no cover - torn down mid-adopt
                continue

    def _redraw(self, width: int, height: int) -> None:
        """Paint the section's header rule - and nothing else.

        This used to draw a filled, rounded, outlined rectangle behind every
        section, which is what made the console read as a stack of boxes. A
        section is now defined by its label and a single hairline beneath it;
        the separation between sections comes from whitespace. The rule is
        drawn only when the section is titled, because an untitled group has
        nothing to underline.
        """
        if width <= 2 or height <= 2 or (width, height) == self._drawn:
            return
        self._drawn = (width, height)
        self.delete("panel")
        if self.header is None:
            return
        # Sits under the header text, inset by the accent marker's width so
        # the rule starts where the label does.
        y = self._rule_y()
        if y <= 0:
            return
        self.create_line(
            0, y, width - 1, y, fill=PALETTE.border, tags="panel",
        )
        self.tag_lower("panel")

    def _rule_y(self) -> int:
        """Y position of the header rule, measured from the real header."""
        try:
            if not self.header.winfo_ismapped():  # type: ignore[union-attr]
                return 0
            return int(self.header.winfo_y() + self.header.winfo_height() + 5)  # type: ignore[union-attr]
        except (tk.TclError, AttributeError):  # pragma: no cover - not mapped
            return 0

    def set_subtitle(self, text: str) -> None:
        """Update (or create) the right-hand subtitle."""
        if self.subtitle_label is not None:
            self.subtitle_label.configure(text=text)
        elif self.header is not None:
            self.subtitle_label = ttk.Label(
                self.header, text=text, style="CardHeaderMuted.TLabel"
            )
            self.subtitle_label.pack(side="right")

    def add_header_widget(self, widget: tk.Widget, side: str = "right") -> None:
        """Place a control in the card header."""
        if self.header is not None:
            widget.pack(in_=self.header, side=side, padx=(6, 0))

    @property
    def fill(self) -> str:
        """The panel colour, for children that must match it."""
        return self._fill


#: How long a changed metric holds its highlight. Long enough to catch the eye
#: on a wall display, short enough not to distract from reading the number.
FLASH_MS = 700

#: Width the tile's caption wraps at, which is what bounds the tile's own
#: requested width and therefore how many fit on one row.
DETAIL_WRAP = 140


class StatCard(ttk.Frame):
    """A single headline metric, optionally with a trend and a sparkline.

    ``0`` is displayed as ``0`` - never as a dash and never hidden - because a
    genuine zero is meaningful information on a monitoring console (§72).

    The trend arrow and the sparkline are drawn only from stored measurements
    the caller supplies. With nothing to compare against, the trend area stays
    empty rather than implying a direction (§1). Clicking a tile opens the
    screen that owns the number.
    """

    def __init__(
        self,
        parent: tk.Misc,
        label: str,
        *,
        value: str = "0",
        detail: str = "",
        accent: str = "",
        fonts: Fonts | None = None,
        on_click: Callable[[], None] | None = None,
        sparkline: bool = False,
        tooltip: str = "",
    ) -> None:
        """Create the metric tile."""
        super().__init__(parent, style="Tile.TFrame", padding=(0, 0))
        # Resolved here, not in the signature: a default argument is
        # evaluated once at import, which would pin this to whichever
        # theme was active then and never follow a switch.
        accent = accent or PALETTE.accent
        self._accent = accent
        self._fonts = fonts
        #: The first value is the baseline, not a change, so it never flashes.
        self._seen_a_value = False
        self._flash_job: str | None = None

        # A full-height accent edge, flush with the panel's own border, so a
        # row of tiles reads as a colour-coded strip before any number is read.
        self._bar = tk.Frame(self, background=accent, width=3)
        self._bar.pack(side="left", fill="y")

        content = ttk.Frame(self, style="Tile.TFrame", padding=(12, 10, 12, 10))
        content.pack(side="left", fill="both", expand=True)

        heading = ttk.Frame(content, style="Tile.TFrame")
        heading.pack(fill="x")
        self._label = ttk.Label(heading, text=label.upper(), style="TileLabel.TLabel")
        self._label.pack(side="left")

        # The trend sits beside the value rather than the label: values are
        # short, so the two never compete for the tile's width.
        value_row = ttk.Frame(content, style="Tile.TFrame")
        value_row.pack(fill="x", pady=(2, 0))
        self._value = ttk.Label(value_row, text=value, style="TileValue.TLabel")
        self._value.pack(side="left")
        self._trend = ttk.Label(value_row, text="", style="TileLabel.TLabel")
        self._trend.pack(side="right", pady=(8, 0))
        # The detail line wraps rather than widening the tile: a long caption
        # would otherwise force every tile on the row wider and push the last
        # one off the screen.
        self._detail = ttk.Label(
            content, text=detail, style="TileMuted.TLabel",
            wraplength=DETAIL_WRAP, justify="left",
        )
        self._detail.pack(anchor="w", fill="x")

        self._sparkline: Any = None
        if sparkline:
            from aethra_sec.ui.widgets.charts import Sparkline

            self._sparkline = Sparkline(content, height=24, colour=accent)
            self._sparkline.pack(fill="x", pady=(6, 0))

        self._clickable = tuple(
            widget for widget in (
                self, content, heading, self._label, self._value, self._detail,
                self._trend,
            )
        )
        if on_click is not None:
            for widget in self._clickable:
                widget.bind("<Button-1>", lambda _event: on_click())
                widget.configure(cursor="hand2")
            self.bind("<Enter>", self._on_enter, add="+")
            self.bind("<Leave>", self._on_leave, add="+")

        if tooltip:
            from aethra_sec.ui.widgets.tooltip import Tooltip

            Tooltip(self, tooltip)

    def _on_enter(self, _event: tk.Event) -> None:
        """Lift the tile while the pointer is over it."""
        self.configure(style="TileHover.TFrame")

    def _on_leave(self, _event: tk.Event) -> None:
        """Restore the resting surface."""
        self.configure(style="Tile.TFrame")

    def update_value(
        self, value: str, detail: str = "", accent: str | None = None
    ) -> None:
        """Update the tile from real data, marking a value that moved.

        A console left on a wall is read by glancing at it. When a figure
        actually changes, the tile's edge pulses once so the change is noticed
        without the operator having to remember the previous number.
        """
        changed = value != self._value.cget("text")
        self._value.configure(text=value)
        self._detail.configure(text=detail)
        if accent:
            self._accent = accent
            self._bar.configure(background=accent)
            self._value.configure(foreground=PALETTE.text)
        if changed and self._seen_a_value and motion_enabled():
            self._flash()
        self._seen_a_value = True

    def _flash(self) -> None:
        """Briefly widen and brighten the accent edge, then settle back."""
        if self._flash_job is not None:
            try:
                self.after_cancel(self._flash_job)
            except (tk.TclError, ValueError):  # pragma: no cover - already fired
                pass
        try:
            self._bar.configure(background=PALETTE.text, width=5)
        except tk.TclError:  # pragma: no cover - widget torn down
            return
        self._flash_job = self.after(FLASH_MS, self._settle)

    def _settle(self) -> None:
        """Return the accent edge to its resting appearance."""
        self._flash_job = None
        try:
            self._bar.configure(background=self._accent, width=3)
        except tk.TclError:  # pragma: no cover - widget torn down
            pass

    def update_trend(self, current: float, previous: float | None) -> None:
        """Show the change against a comparable earlier period.

        ``previous`` of ``None`` means there is no comparable period stored, and
        the tile then shows nothing rather than a fabricated 0%.
        """
        from aethra_sec.utils.formatting import format_count

        if previous is None:
            self._trend.configure(text="", foreground=PALETTE.text_dim)
            return
        delta = current - previous
        if abs(delta) < 1e-9:
            self._trend.configure(text="—", foreground=PALETTE.text_dim)
            return
        arrow = "▲" if delta > 0 else "▼"
        magnitude = (
            f"{abs(delta / previous * 100):.0f}%" if previous
            else format_count(int(abs(delta)))
        )
        self._trend.configure(
            text=f"{arrow}{magnitude}",
            foreground=PALETTE.medium if delta > 0 else PALETTE.low,
        )

    def update_sparkline(self, values: Sequence[float]) -> None:
        """Plot the stored series the tile's number came from."""
        if self._sparkline is not None:
            self._sparkline.set_values(values, colour=self._accent)


class StatusIndicator(ttk.Frame):
    """A subsystem status light (§10).

    The dot is green only when the subsystem genuinely answered a probe.
    """

    def __init__(
        self,
        parent: tk.Misc,
        name: str,
        *,
        state: str = "UNKNOWN",
        detail: str = "",
        compact: bool = False,
    ) -> None:
        """Create the indicator."""
        super().__init__(parent, style="Card.TFrame", padding=(0, 4))
        self._dot = tk.Canvas(
            self, width=12, height=12, highlightthickness=0,
            background=PALETTE.background,
        )
        self._dot.pack(side="left", padx=(0, 8))
        self._circle = self._dot.create_oval(
            2, 2, 10, 10, fill=state_colour(state), outline=""
        )

        text_frame = ttk.Frame(self, style="Card.TFrame")
        text_frame.pack(side="left", fill="x", expand=True)
        self._name = ttk.Label(text_frame, text=name, style="Card.TLabel")
        self._name.pack(anchor="w")
        self._state = ttk.Label(
            text_frame, text=str(state), style="CardMuted.TLabel"
        )
        self._state.pack(anchor="w")
        self._detail_label: ttk.Label | None = None
        if not compact:
            self._detail_label = ttk.Label(
                text_frame, text=detail, style="CardDim.TLabel", wraplength=320,
                justify="left",
            )
            self._detail_label.pack(anchor="w")

    def update_state(self, state: str, detail: str = "") -> None:
        """Apply a real probe result."""
        colour = state_colour(state)
        self._dot.itemconfigure(self._circle, fill=colour)
        self._state.configure(text=str(state), foreground=colour)
        if self._detail_label is not None:
            self._detail_label.configure(text=detail)


class SeverityBadge(ttk.Label):
    """A coloured severity/status chip."""

    def __init__(self, parent: tk.Misc, value: str = "", kind: str = "severity") -> None:
        """Create the badge."""
        super().__init__(parent, text=str(value), style="Card.TLabel")
        self._kind = kind
        self.update_value(value)

    def update_value(self, value: str) -> None:
        """Recolour for a new value."""
        colour = {
            "severity": severity_colour,
            "state": state_colour,
            "status": status_colour,
        }.get(self._kind, severity_colour)(value)
        self.configure(text=str(value), foreground=colour)


class EmptyState(ttk.Frame):
    """The honest placeholder shown when there is genuinely nothing to show."""

    def __init__(
        self,
        parent: tk.Misc,
        message: str = "No data available",
        *,
        detail: str = "",
        icon: str = "",
        action_label: str = "",
        on_action: Callable[[], None] | None = None,
    ) -> None:
        """Create the empty state."""
        super().__init__(parent, style="Card.TFrame", padding=24)
        inner = ttk.Frame(self, style="Card.TFrame")
        inner.place(relx=0.5, rely=0.5, anchor="center")

        if icon:
            ttk.Label(
                inner, text=icon, style="CardDim.TLabel", font=("TkDefaultFont", 22)
            ).pack(pady=(0, 6))
        self._message = ttk.Label(inner, text=message, style="CardMuted.TLabel")
        self._message.pack()
        self._detail = ttk.Label(
            inner, text=detail, style="CardDim.TLabel", wraplength=460,
            justify="center",
        )
        if detail:
            self._detail.pack(pady=(6, 0))
        if action_label and on_action is not None:
            ttk.Button(
                inner, text=action_label, style="Ghost.TButton", command=on_action
            ).pack(pady=(12, 0))

    def update_message(self, message: str, detail: str = "") -> None:
        """Change the message (for example when capture starts)."""
        self._message.configure(text=message)
        self._detail.configure(text=detail)
        if detail and not self._detail.winfo_ismapped():
            self._detail.pack(pady=(6, 0))


class KeyValueList(ttk.Frame):
    """A two-column detail list used across investigation views."""

    def __init__(
        self, parent: tk.Misc, *, label_width: int = 22, wraplength: int = 520
    ) -> None:
        """Create an empty list."""
        super().__init__(parent, style="Card.TFrame")
        self._label_width = label_width
        self._wraplength = wraplength
        self._rows: list[tuple[ttk.Label, ttk.Label]] = []

    def set_items(self, items: list[tuple[str, str]], colours: dict[str, str] | None = None) -> None:
        """Replace the contents."""
        for label, value in self._rows:
            label.destroy()
            value.destroy()
        self._rows.clear()

        palette = colours or {}
        for row, (key, value) in enumerate(items):
            key_label = ttk.Label(
                self, text=f"{key}", style="CardDim.TLabel", width=self._label_width,
                anchor="w",
            )
            key_label.grid(row=row, column=0, sticky="nw", pady=2, padx=(0, 10))
            value_label = ttk.Label(
                self, text=value or "-", style="Card.TLabel",
                wraplength=self._wraplength, justify="left", anchor="w",
            )
            if key in palette:
                value_label.configure(foreground=palette[key])
            value_label.grid(row=row, column=1, sticky="w", pady=2)
            self._rows.append((key_label, value_label))
        self.columnconfigure(1, weight=1)


#: Widget classes that scroll themselves. The wheel is left alone over these so
#: a table or a text pane inside a scrollable page keeps its own scrolling.
_SELF_SCROLLING_CLASSES = frozenset(
    {"Treeview", "Text", "Canvas", "Listbox", "TCombobox"}
)

#: Wheel sequences: ``<MouseWheel>`` on Windows and macOS, buttons 4/5 on X11.
_WHEEL_SEQUENCES = ("<MouseWheel>", "<Button-4>", "<Button-5>")


class ScrollableFrame(ttk.Frame):
    """A vertically scrollable container for tall screens."""

    def __init__(
        self,
        parent: tk.Misc,
        *,
        padding: int = 0,
        style: str = "TFrame",
        background: str = "",
        autohide: bool = False,
    ) -> None:
        """Create the scroll host; add children to :attr:`interior`.

        ``style`` and ``background`` let the scroller sit on a surface other
        than the page - the sidebar, for instance - without a seam showing
        where the canvas meets its surroundings.
        """
        super().__init__(parent, style=style)
        # Resolved here rather than in the signature: a palette value used
        # as a default argument is evaluated at import and would keep the
        # starting theme's colour for the life of the process.
        background = background or PALETTE.background
        self._canvas = tk.Canvas(
            self, background=background, highlightthickness=0, borderwidth=0
        )
        self._scrollbar = ttk.Scrollbar(
            self, orient="vertical", command=self._canvas.yview
        )
        # The interior must be a *child of the canvas*: a canvas only clips and
        # scrolls its own descendants. Parented to the frame instead, it draws
        # at full height over everything around it and the scrollbar moves a
        # viewport that nothing follows.
        self.interior = ttk.Frame(self._canvas, style=style, padding=padding)

        self._window = self._canvas.create_window(
            (0, 0), window=self.interior, anchor="nw"
        )
        self._canvas.configure(yscrollcommand=self._scrollbar.set, width=1)
        # The scrollbar is packed first so it reserves its width: a canvas asks
        # for a default width far wider than a narrow host such as the sidebar,
        # and packing it first leaves the scrollbar with no room at all.
        self._scrollbar.pack(side="right", fill="y")
        self._canvas.pack(side="left", fill="both", expand=True)
        #: True while the scrollbar is on screen.
        self._bar_shown = True
        #: Opt-in: hide the scrollbar while the content fits. Off by default,
        #: because a host too narrow to give the bar its width later (the
        #: sidebar) needs it reserved from the start.
        self._autohide = autohide

        self._wheel_bound: set[str] = set()
        self.interior.bind("<Configure>", self._on_interior_configure)
        self._canvas.bind("<Configure>", self._on_canvas_configure)
        self._bind_wheel()

    def _on_interior_configure(self, _event: tk.Event) -> None:
        """Resize the scroll region to the content, and catch up on new children."""
        self._canvas.configure(scrollregion=self._canvas.bbox("all"))
        # Children are added after construction, so this is where they become
        # visible to the wheel.
        self._bind_wheel_to_descendants(self.interior)
        self._sync_scrollbar()

    def _on_canvas_configure(self, event: tk.Event) -> None:
        """Keep the interior as wide as the canvas."""
        self._canvas.itemconfigure(self._window, width=event.width)
        self._sync_scrollbar()

    def _sync_scrollbar(self) -> None:
        """Show the scrollbar only while the content overflows."""
        if not self._autohide:
            return
        try:
            needed = self.interior.winfo_reqheight() > self._canvas.winfo_height() + 1
        except tk.TclError:  # pragma: no cover - during teardown
            return
        if needed == self._bar_shown:
            return
        self._bar_shown = needed
        if needed:
            self._scrollbar.pack(side="right", fill="y", before=self._canvas)
        else:
            self._scrollbar.pack_forget()
            self._canvas.yview_moveto(0)

    # ------------------------------------------------------------------
    # Wheel routing
    # ------------------------------------------------------------------
    def _bind_wheel(self) -> None:
        """Route the wheel to this canvas from anywhere inside it.

        Tk delivers a wheel event to the deepest widget under the pointer, and
        the content covers this frame completely, so a binding on the frame
        alone never fires. Binding each descendant keeps the wheel working over
        the content itself, and does it without ``bind_all`` - an application
        binding would be shared with every other scroller on screen.
        """
        self._bind_wheel_to(self._canvas)
        self._bind_wheel_to(self.interior)

    def _bind_wheel_to(self, widget: tk.Misc) -> None:
        """Attach the wheel handler to one widget."""
        for sequence in _WHEEL_SEQUENCES:
            try:
                widget.bind(sequence, self._on_wheel, add="+")
            except tk.TclError:  # pragma: no cover - widget torn down
                return
        self._wheel_bound.add(str(widget))

    def _bind_wheel_to_descendants(self, parent: tk.Misc) -> None:
        """Bind the wheel on every child that does not scroll itself."""
        try:
            children = parent.winfo_children()
        except tk.TclError:  # pragma: no cover - widget torn down
            return
        for child in children:
            if child.winfo_class() in _SELF_SCROLLING_CLASSES:
                continue
            if str(child) not in self._wheel_bound:
                self._bind_wheel_to(child)
            self._bind_wheel_to_descendants(child)

    def _on_wheel(self, event: tk.Event) -> str | None:
        """Scroll, handling both the Windows/macOS and X11 wheel conventions."""
        if not self._can_scroll():
            # Nothing to scroll here: let the event reach an outer scroller
            # rather than swallowing it.
            return None
        steps = self._wheel_steps(event)
        if not steps:
            return None
        self._canvas.yview_scroll(steps, "units")
        return "break"

    def _can_scroll(self) -> bool:
        """True when the content is taller than the viewport."""
        try:
            first, last = self._canvas.yview()
        except (tk.TclError, ValueError):  # pragma: no cover - widget torn down
            return False
        return (last - first) < 1.0

    @staticmethod
    def _wheel_steps(event: tk.Event) -> int:
        """Lines to scroll for one wheel event, or ``0`` if it is not a wheel.

        X11 reports the wheel as buttons 4 and 5. Windows and macOS report a
        signed ``delta``: 120 per notch on a mouse, but smaller increments from
        a trackpad, which is why a partial notch still moves one line.
        """
        number = getattr(event, "num", None)
        if number == 4:
            return -1
        if number == 5:
            return 1
        delta = int(getattr(event, "delta", 0) or 0)
        if not delta:
            return 0
        lines = max(1, abs(delta) // 120)
        return -lines if delta > 0 else lines


def parse_pad(value: Any) -> tuple[int, int]:
    """Normalise a Tk pad value into a ``(leading, trailing)`` pixel pair.

    ``pack_info`` hands padding back in whichever form it was given - an int,
    a string, or a pair - so a caller that wants to measure it has to agree on
    one shape first.
    """
    if isinstance(value, (list, tuple)):
        parts = list(value)
    else:
        parts = str(value).split()
    numbers: list[int] = []
    for part in parts:
        try:
            numbers.append(int(str(part)))
        except ValueError:  # a unit suffix such as "2m"; not used here
            return (0, 0)
    if not numbers:
        return (0, 0)
    if len(numbers) == 1:
        return (numbers[0], numbers[0])
    return (numbers[0], numbers[1])


def wrap_controls(
    widths: Sequence[int],
    available: int,
    *,
    reserved: int = 0,
    captions: Sequence[bool] = (),
) -> list[list[int]]:
    """Group control indices into lines that fit ``available`` pixels.

    Args:
        widths: pixels each control needs, in display order.
        available: pixels the line has.
        reserved: pixels already spoken for on the first line by controls
            pinned to its right edge.
        captions: per control, whether it is a caption for the control after
            it. A caption is carried down to the next line rather than being
            left stranded above the field it names.

    Returns:
        One list of indices per line. Always at least one line, so a control
        wider than the bar still gets placed rather than dropped.
    """
    lines: list[list[int]] = [[]]
    used = reserved
    for index, width in enumerate(widths):
        if lines[-1] and used + width > available:
            carried: list[int] = []
            while (
                len(lines[-1]) > 1
                and lines[-1][-1] < len(captions)
                and captions[lines[-1][-1]]
            ):
                carried.insert(0, lines[-1].pop())
            lines.append(carried)
            used = sum(widths[position] for position in carried)
        lines[-1].append(index)
        used += width
    return lines


@dataclass
class _BarItem:
    """One control in a :class:`ControlBar`, with the padding it was given."""

    widget: tk.Misc
    side: str
    fill: str = "none"
    padx: tuple[int, int] = (0, 0)
    pady: tuple[int, int] = (0, 0)
    #: True for a control that may be hidden outright when the bar is short of
    #: room - a keyboard hint, say, which is worth less than the data it would
    #: otherwise push off the line.
    optional: bool = False

    @property
    def width(self) -> int:
        """Pixels this control needs, padding included."""
        return self.widget.winfo_reqwidth() + self.padx[0] + self.padx[1]


class ControlBar(ttk.Frame):
    """A row of controls that wraps instead of clipping.

    A screen with many controls - the alert queue has nine actions, and its
    filter row has four fields plus two buttons - runs out of room long before
    the window does anything unusual. A single packed row answers that by
    clipping whatever was packed last, so on a narrow window an action, or the
    record count, simply disappears.

    So this bar reflows. Controls that do not fit wrap onto the next line, and
    trailing controls (a count, usually) are measured before the leading ones
    are placed, so the two never fight over the same pixels.

    Controls a screen packs into the bar itself are adopted, which means a
    plain ``ttk.Frame`` full of filter fields becomes a wrapping bar by
    changing only the class it is built from.
    """

    #: Vertical gap between wrapped lines.
    LINE_GAP = 6

    def __init__(
        self, parent: tk.Misc, *, padding: tuple[int, ...] = (0, 0)
    ) -> None:
        """Create an empty bar."""
        super().__init__(parent, style="Card.TFrame", padding=padding)
        self._pad_x = int(padding[0]) if padding else 0
        #: Controls to lay out, in the order they were added.
        self._items: list[_BarItem] = []
        #: One frame per rendered line, reused as the bar grows and shrinks.
        self._lines: list[ttk.Frame] = []
        self._laid_out: tuple[int, int] = (-1, -1)
        self.bind("<Configure>", self._on_configure, add="+")

    # ------------------------------------------------------------------
    # Building
    # ------------------------------------------------------------------
    def add(
        self,
        widget: tk.Misc,
        *,
        side: str = "left",
        fill: str = "none",
        padx: tuple[int, int] = (0, 0),
        pady: tuple[int, int] = (0, 0),
        optional: bool = False,
    ) -> None:
        """Lay out a widget the caller built, instead of packing it directly."""
        self._place(
            _BarItem(
                widget=widget, side=side, fill=fill,
                padx=padx, pady=pady, optional=optional,
            )
        )

    # ------------------------------------------------------------------
    # Layout
    # ------------------------------------------------------------------
    def _place(self, item: _BarItem) -> None:
        """Register a control and lay the bar out again."""
        self._items.append(item)
        self._relayout(force=True)

    def _on_configure(self, _event: tk.Event) -> None:
        """Re-wrap when the available width changes."""
        self._relayout()

    def _line(self, index: int) -> ttk.Frame:
        """The frame holding line ``index``, created on first use."""
        while len(self._lines) <= index:
            self._lines.append(ttk.Frame(self, style="Card.TFrame"))
        return self._lines[index]

    def _adopt_strays(self) -> None:
        """Take in controls a screen packed into the bar itself.

        Their original padding is kept, so adopting a row does not shift the
        spacing a screen chose for it.
        """
        known = {str(item.widget) for item in self._items}
        for slave in self.pack_slaves():
            if slave in self._lines or str(slave) in known:
                continue
            info = slave.pack_info()
            self._items.append(
                _BarItem(
                    widget=slave,
                    side=str(info.get("side", "left")),
                    fill=str(info.get("fill", "none")),
                    padx=parse_pad(info.get("padx", 0)),
                    pady=parse_pad(info.get("pady", 0)),
                )
            )

    def _relayout(self, *, force: bool = False) -> None:
        """Wrap the controls to the current width."""
        self._adopt_strays()
        if not self._items:
            return
        width = self.winfo_width() - 2 * self._pad_x
        # Before the bar is mapped its width is meaningless, so lay everything
        # on one line: the frame then reports its natural size and the parent
        # can allocate space for it. The first <Configure> wraps it properly.
        single_line = width <= 1

        state = (width, len(self._items))
        if state == self._laid_out and not force:
            return
        self._laid_out = state

        trailing = [item for item in self._items if item.side == "right"]
        leading = [item for item in self._items if item.side != "right"]

        # Controls marked optional are hidden rather than wrapped: a hint that
        # costs the bar a second line is not worth the line.
        total = sum(item.width for item in leading + trailing)
        for item in [entry for entry in trailing if entry.optional]:
            if single_line or total <= width:
                break
            trailing.remove(item)
            item.widget.pack_forget()
            total -= item.width

        available = width
        if single_line:
            available = sum(item.width for item in self._items) + 1
        # A label is read as the caption of the control after it, so a wrap
        # never leaves "Period" on one line and its menu on the next.
        grouped = wrap_controls(
            [item.width for item in leading],
            available,
            reserved=sum(item.width for item in trailing),
            captions=[isinstance(item.widget, ttk.Label) for item in leading],
        )
        lines = [[leading[position] for position in line] for line in grouped]

        for index, line_items in enumerate(lines):
            line = self._line(index)
            line.pack(fill="x", pady=(0 if index == 0 else self.LINE_GAP, 0))
            placed = list(line_items)
            if index == 0:
                placed = trailing + placed
            for item in placed:
                item.widget.pack(
                    in_=line,
                    side="right" if item.side == "right" else "left",
                    padx=item.padx,
                    pady=item.pady,
                    fill=item.fill,
                )
                # A control packed into a sibling frame is still a child of the
                # bar, and the line frame - created later - sits above it in
                # the stacking order. Without this the control would be laid
                # out correctly and then painted over.
                item.widget.lift(line)
        for spare in self._lines[len(lines):]:
            spare.pack_forget()


class FilterBar(ControlBar):
    """A wrapping row for a screen's own filter fields.

    It adds no factories: screens build their labels, entries and combo boxes
    themselves and pack them here, exactly as they did into a plain frame.
    """


class Toolbar(ControlBar):
    """A wrapping row of actions above a table."""

    #: Horizontal gap between neighbouring controls.
    GAP = 6

    def add_button(
        self,
        text: str,
        command: Callable[[], None],
        *,
        style: str = "Ghost.TButton",
        side: str = "left",
        enabled: bool = True,
    ) -> ttk.Button:
        """Add a button and return it so callers can enable/disable it."""
        button = ttk.Button(self, text=text, command=command, style=style)
        if not enabled:
            button.state(["disabled"])
        self._place(_BarItem(widget=button, side=side, padx=self._gap(side)))
        return button

    def add_label(self, text: str, *, side: str = "left") -> ttk.Label:
        """Add a label."""
        label = ttk.Label(self, text=text, style="CardMuted.TLabel")
        self._place(_BarItem(widget=label, side=side, padx=self._gap(side)))
        return label

    def add_checkbox(
        self,
        text: str,
        variable: tk.BooleanVar,
        command: Callable[[], None],
        *,
        side: str = "left",
    ) -> ttk.Checkbutton:
        """Add a toggle and return it.

        Used for a filter an operator flips often enough that it belongs on
        the toolbar rather than behind a menu.
        """
        box = ttk.Checkbutton(
            self, text=text, variable=variable, command=command,
            style="Toolbar.TCheckbutton",
        )
        self._place(_BarItem(widget=box, side=side, padx=self._gap(side)))
        return box

    def add_separator(self) -> None:
        """Add a vertical rule."""
        rule = tk.Frame(self, background=PALETTE.border, width=1)
        self._place(
            _BarItem(
                widget=rule, side="left", fill="y", padx=(8, 8), pady=(2, 2)
            )
        )

    def _gap(self, side: str) -> tuple[int, int]:
        """Padding that puts the gap on the inward side of the control."""
        return (self.GAP, 0) if side == "right" else (0, self.GAP)


@dataclass(frozen=True)
class SummaryCell:
    """One figure in a :class:`SummaryStrip`."""

    key: str
    label: str
    colour: str = ""
    #: Opened when the cell is clicked, where the screen offers a filtered view.
    on_click: Callable[[], None] | None = None
    tooltip: str = ""
    #: A short line under the label - a threshold, a unit, a qualifier. It is
    #: the accessible form of whatever the tooltip explains at length, so a
    #: cell never depends on hover alone to be understood.
    caption: str = ""


class SummaryStrip(ttk.Frame):
    """A row of counts that says what a queue contains before it is read.

    A table answers "what are the records?"; this answers "how bad is it?" -
    which is the question an operator actually arrives with. It is one
    component used by every queue in the console so the answer looks the same
    on each of them.

    Every figure is supplied by the screen from stored records. A cell whose
    count is unknown shows nothing rather than a zero, because on a security
    console those two mean very different things.
    """

    #: Narrowest a cell may be before the strip wraps.
    MIN_CELL_WIDTH = 132

    def __init__(
        self,
        parent: tk.Misc,
        cells: Sequence[SummaryCell],
        *,
        fonts: Fonts | None = None,
    ) -> None:
        """Build the strip; call :meth:`update_counts` to fill it in."""
        super().__init__(parent, style="Tile.TFrame", padding=(1, 1))
        self._fonts = fonts
        self._cells = list(cells)
        self._values: dict[str, ttk.Label] = {}
        self._frames: dict[str, ttk.Frame] = {}
        self._columns = 0

        self._grid = ttk.Frame(self, style="Tile.TFrame")
        self._grid.pack(fill="x")
        for cell in self._cells:
            holder = ttk.Frame(self._grid, style="Tile.TFrame", padding=(14, 10))
            accent = cell.colour or PALETTE.accent
            tk.Frame(holder, background=accent, width=2, height=26).pack(
                side="left", padx=(0, 12)
            )
            text = ttk.Frame(holder, style="Tile.TFrame")
            text.pack(side="left", fill="x", expand=True)
            value = ttk.Label(text, text="-", style="TileValueSm.TLabel")
            value.pack(anchor="w")
            ttk.Label(text, text=cell.label.upper(), style="TileLabel.TLabel").pack(
                anchor="w"
            )
            if cell.caption:
                # Dim and small, so a third line costs the strip very little
                # height. It carries the same fact as the tooltip, in text,
                # for anyone who does not hover.
                ttk.Label(
                    text, text=cell.caption, style="TileDim.TLabel",
                ).pack(anchor="w")
            value.configure(foreground=accent)
            if cell.tooltip:
                # One tooltip per cell, bound to the holder. The tooltip
                # component owns its own show/hide and destroys its window
                # with the widget, so this cannot accumulate on a rebuild.
                attach_tooltip(holder, cell.tooltip)
            if cell.on_click is not None:
                for widget in (holder, text, value):
                    widget.configure(cursor="hand2")
                    widget.bind("<Button-1>", lambda _e, c=cell: c.on_click())
            self._values[cell.key] = value
            self._frames[cell.key] = holder

        self._layout(len(self._cells))
        self.bind("<Configure>", self._on_configure)

    def _on_configure(self, event: tk.Event) -> None:
        """Wrap the cells when the window cannot hold them on one line."""
        fits = max(1, min(len(self._cells), int(event.width) // self.MIN_CELL_WIDTH))
        self._layout(fits)

    def _layout(self, columns: int) -> None:
        """Place the cells in ``columns`` columns."""
        columns = max(1, columns)
        if columns == self._columns:
            return
        self._columns = columns
        for index, cell in enumerate(self._cells):
            holder = self._frames[cell.key]
            holder.grid(
                row=index // columns, column=index % columns, sticky="nsew",
                padx=(0, 1), pady=(0, 1),
            )
        for column in range(columns):
            self._grid.columnconfigure(column, weight=1, uniform="summary")
        for spare in range(columns, len(self._cells) + 1):
            self._grid.columnconfigure(spare, weight=0, uniform="")

    def update_counts(self, counts: dict[str, Any]) -> None:
        """Show the supplied figures; a missing key clears its cell."""
        for key, label in self._values.items():
            if key not in counts:
                label.configure(text="-")
                continue
            value = counts[key]
            label.configure(
                text=f"{value:,}" if isinstance(value, int) else str(value)
            )
