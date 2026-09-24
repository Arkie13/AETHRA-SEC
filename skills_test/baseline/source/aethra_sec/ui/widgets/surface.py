"""Rounded, elevated surfaces drawn on a Canvas (§60).

A ``ttk.Frame`` can only ever be a hard-edged rectangle: ttk has no radius, no
shadow and no gradient. Every panel in the console was therefore a flat box
with a one-pixel border, and no amount of re-colouring changes what that reads
as - which is why the interface kept looking like the same interface.

So the panel stops being a frame. :class:`Surface` is a Canvas that paints a
rounded body, a soft drawn shadow beneath it and an optional accent band along
its top edge, then hosts ordinary widgets inside itself through
``create_window``. Content is built exactly as before; only the thing it sits
on has changed.

Tk has no alpha channel, so the shadow is not transparency - it is a short
ladder of rounded rectangles blended by hand toward the page colour underneath.
That is also why a surface must be told the colour it is sitting on: it cannot
sample it.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Callable

from aethra_sec.ui.theme import PALETTE, Fonts
from aethra_sec.ui.widgets.chips import rounded_rectangle

#: Corner radius shared by every surface, so panels look like one family.
RADIUS = 14

#: How far the drawn shadow reaches below and to the side of a surface.
SHADOW_DEPTH = 6

#: Height of the trend band across the foot of a metric tile.
SPARK_HEIGHT = 30

#: Height of the accent band a surface can carry along its top edge.
ACCENT_HEIGHT = 3


def blend(colour: str, towards: str, amount: float) -> str:
    """Mix ``colour`` toward ``towards`` by ``amount`` (0.0-1.0).

    Used for the shadow ladder and for hover states, both of which need a
    colour "between" two others on a toolkit with no alpha channel.
    """
    amount = max(0.0, min(1.0, amount))
    start = tuple(int(colour[index:index + 2], 16) for index in (1, 3, 5))
    end = tuple(int(towards[index:index + 2], 16) for index in (1, 3, 5))
    mixed = tuple(
        int(round(a + (b - a) * amount)) for a, b in zip(start, end)
    )
    return "#%02X%02X%02X" % mixed


class Surface(tk.Canvas):
    """A rounded panel with a drawn shadow, hosting ordinary widgets.

    Args:
        page: the colour behind this surface. The shadow and the rounded
            corners are painted against it, so it has to be told.
        fill: the surface colour.
        accent: colour of the band along the top edge; empty for none.
        padding: inset applied to the hosted content.
    """

    def __init__(
        self,
        parent: tk.Misc,
        *,
        page: str = "",
        fill: str = "",
        accent: str = "",
        radius: int = RADIUS,
        padding: tuple[int, int] = (20, 18),
        shadow: bool = True,
    ) -> None:
        """Create the surface and its content frame."""
        self._page = page or PALETTE.background
        self._fill = fill or PALETTE.surface
        self._accent = accent
        self._radius = radius
        self._shadow = shadow
        super().__init__(
            parent, background=self._page, highlightthickness=0, borderwidth=0,
        )

        style_name = f"Surface{id(self)}.TFrame"
        ttk.Style().configure(style_name, background=self._fill)
        self.body = ttk.Frame(self, style=style_name, padding=padding)
        self._body_style = style_name
        self._window = self.create_window(0, 0, window=self.body, anchor="nw")
        self._drawn: tuple[int, int] = (-1, -1)
        self.bind("<Configure>", self._on_configure)

    # ------------------------------------------------------------------
    @property
    def fill(self) -> str:
        """The surface colour, for children that must match it."""
        return self._fill

    def set_fill(self, colour: str) -> None:
        """Repaint the surface in a different colour (hover, selection)."""
        if colour == self._fill:
            return
        self._fill = colour
        ttk.Style().configure(self._body_style, background=colour)
        self._drawn = (-1, -1)
        self._redraw(self.winfo_width(), self.winfo_height())

    def fit_height(self, extra: int = 0) -> None:
        """Size the canvas to the height its content actually needs.

        A stated height is wrong on any machine whose fonts differ from the
        one it was chosen on - which is every other machine - and the symptom
        is a caption sliced in half. The content is measured instead.
        """
        def apply() -> None:
            try:
                needed = self.body.winfo_reqheight()
            except tk.TclError:  # pragma: no cover - torn down
                return
            self.configure(height=needed + SHADOW_DEPTH + extra)
        self.after_idle(apply)

    def set_accent(self, colour: str) -> None:
        """Change the top band's colour."""
        if colour == self._accent:
            return
        self._accent = colour
        self._drawn = (-1, -1)
        self._redraw(self.winfo_width(), self.winfo_height())

    # ------------------------------------------------------------------
    def _on_configure(self, event: tk.Event) -> None:
        """Repaint and resize the hosted frame to the new size."""
        self._redraw(int(event.width), int(event.height))

    def _redraw(self, width: int, height: int) -> None:
        """Paint the shadow, the body and the accent band."""
        if width <= 2 or height <= 2:
            return
        if (width, height) == self._drawn:
            return
        self._drawn = (width, height)

        self.delete("surface")
        depth = SHADOW_DEPTH if self._shadow else 0
        right, bottom = width - 1, height - 1 - depth

        # The shadow: a short ladder blended toward the page, drawn outermost
        # first so each rung sits on top of the one beneath it.
        for step in range(depth, 0, -1):
            spread = step
            tint = blend(self._page, PALETTE.shadow, 0.62 * (1 - (step - 1) / depth))
            rounded_rectangle(
                self, spread, spread, right - spread, bottom + spread,
                self._radius, fill=tint, outline="", tags="surface",
            )

        rounded_rectangle(
            self, 0, 0, right, bottom, self._radius,
            fill=self._fill, outline="", tags="surface",
        )
        # A lit rim along the top curve. One value of light where the surface
        # faces the viewer does more for perceived depth on a dark ground than
        # any amount of shadow beneath it.
        self.create_arc(
            0, 0, self._radius * 2, self._radius * 2, start=90, extent=90,
            style="arc", outline=blend(self._fill, "#FFFFFF", 0.10),
            width=1, tags="surface",
        )
        self.create_line(
            self._radius, 1, right - self._radius, 1,
            fill=blend(self._fill, "#FFFFFF", 0.10), tags="surface",
        )
        self.create_arc(
            right - self._radius * 2, 0, right, self._radius * 2,
            start=0, extent=90, style="arc",
            outline=blend(self._fill, "#FFFFFF", 0.10), width=1, tags="surface",
        )

        if self._accent:
            # Clipped to the body's top edge, so it follows the same curve.
            rounded_rectangle(
                self, 0, 0, right, self._radius * 2, self._radius,
                fill=self._accent, outline="", tags="surface",
            )
            self.create_rectangle(
                0, ACCENT_HEIGHT, right, self._radius * 2,
                fill=self._fill, outline="", tags="surface",
            )

        self.tag_lower("surface")
        self.coords(self._window, 0, 0)
        self.itemconfigure(
            self._window, width=max(1, right), height=max(1, bottom),
        )


class HoverSurface(Surface):
    """A surface that lifts under the pointer and can be clicked."""

    def __init__(
        self,
        parent: tk.Misc,
        *,
        on_click: Callable[[], None] | None = None,
        hover_fill: str = "",
        **kwargs: object,
    ) -> None:
        """Create the surface and bind the pointer behaviour."""
        super().__init__(parent, **kwargs)  # type: ignore[arg-type]
        self._resting = self.fill
        self._ring_colour = hover_fill or PALETTE.border_strong
        self._on_click = on_click
        if on_click is not None:
            self.configure(cursor="hand2")
        self._bind_tree(self)

    def _bind_tree(self, widget: tk.Misc) -> None:
        """Bind hover and click on the surface and everything inside it.

        A child widget swallows the pointer, so binding only the canvas would
        make the tile stop reacting wherever it has content - which is most of
        it.
        """
        widget.bind("<Enter>", self._on_enter, add="+")
        widget.bind("<Leave>", self._on_leave, add="+")
        if self._on_click is not None:
            widget.bind("<Button-1>", self._on_press, add="+")
        for child in widget.winfo_children():
            self._bind_tree(child)

    def bind_children(self) -> None:
        """Re-bind after content has been added."""
        self._bind_tree(self)

    def _on_enter(self, _event: tk.Event) -> None:
        self._set_ring(True)

    def _on_leave(self, _event: tk.Event) -> None:
        self._set_ring(False)

    def _set_ring(self, on: bool) -> None:
        """Outline the surface under the pointer.

        The fill is deliberately left alone: the labels inside carry their own
        style background, so repainting the frame without repainting every one
        of them draws a mismatched box behind each piece of text.
        """
        self.delete("ring")
        if not on:
            return
        width, height = self.winfo_width(), self.winfo_height()
        if width <= 2 or height <= 2:
            return
        rounded_rectangle(
            self, 1, 1, width - 2, height - 2 - SHADOW_DEPTH, self._radius,
            fill="", outline=self._ring_colour, width=2, tags="ring",
        )

    def _on_press(self, _event: tk.Event) -> None:
        if self._on_click is not None:
            self._on_click()


class Pill(tk.Canvas):
    """A filled, rounded status token.

    Severity as coloured text is easy to miss in a dense column. A filled pill
    is not, and it stays distinguishable when the row beneath it is selected.
    """

    def __init__(
        self,
        parent: tk.Misc,
        text: str = "",
        *,
        colour: str = "",
        page: str = "",
        fonts: Fonts | None = None,
        height: int = 22,
    ) -> None:
        """Create the pill, sized to its text."""
        self._page = page or PALETTE.surface
        self._colour = colour or PALETTE.accent
        self._font = fonts.small_bold if fonts else ("TkDefaultFont", 9, "bold")
        self._text = text
        self._height = height
        super().__init__(
            parent, height=height, background=self._page,
            highlightthickness=0, borderwidth=0,
        )
        self._measure()
        self.bind("<Configure>", lambda _e: self._draw())

    def set_value(self, text: str, colour: str = "") -> None:
        """Replace the label, and optionally the colour."""
        self._text = text
        if colour:
            self._colour = colour
        self._measure()
        self._draw()

    def _measure(self) -> None:
        """Size the canvas to the text it has to carry."""
        from tkinter import font as tkfont

        width = tkfont.Font(font=self._font).measure(self._text) + 22
        self.configure(width=max(width, 44))

    def _draw(self) -> None:
        """Paint the pill."""
        self.delete("all")
        width = max(int(self.winfo_width()), int(self["width"]))
        height = max(int(self.winfo_height()), self._height)
        rounded_rectangle(
            self, 1, 2, width - 1, height - 2, (height - 4) / 2,
            fill=blend(self._page, self._colour, 0.22), outline="",
        )
        self.create_text(
            width / 2, height / 2, text=self._text, fill=self._colour,
            font=self._font,
        )


class MetricTile(HoverSurface):
    """A headline figure on its own elevated surface.

    The old tile was a bordered box with a 26pt number and a caption. This one
    gives the number the whole tile: a coloured glyph badge, the figure at
    display size, the caption beneath it, and a sparkline bled across the
    bottom edge rather than boxed inside a panel.

    ``0`` is still shown as ``0``. A genuine zero is information on a
    monitoring console, and hiding it would be the one change that made the
    tile less honest rather than more modern (§72).
    """

    def __init__(
        self,
        parent: tk.Misc,
        label: str,
        *,
        page: str = "",
        colour: str = "",
        glyph: str = "",
        fonts: Fonts | None = None,
        on_click: Callable[[], None] | None = None,
    ) -> None:
        """Build the tile; call :meth:`update_value` to fill it in."""
        colour = colour or PALETTE.accent
        super().__init__(
            parent, page=page or PALETTE.background, fill=PALETTE.surface,
            padding=(20, 16, 20, 12), on_click=on_click,
        )

        self._colour = colour
        self._fonts = fonts
        self._series: list[float] = []

        style = f"MetricBody{id(self)}.TFrame"
        ttk.Style().configure(style, background=self.fill)

        head = ttk.Frame(self.body, style=self._body_style)
        head.pack(fill="x")

        # A tinted rounded badge rather than a bare glyph: it gives the tile a
        # focal point that survives being read from across a room.
        self._badge = tk.Canvas(
            head, width=34, height=34, background=self.fill,
            highlightthickness=0, borderwidth=0,
        )
        rounded_rectangle(
            self._badge, 0, 0, 34, 34, 10,
            fill=blend(self.fill, colour, 0.20), outline="",
        )
        self._glyph = glyph or "●"
        self._badge.create_text(
            17, 17, text=self._glyph, fill=colour,
            font=(fonts.family if fonts else "TkDefaultFont", 14, "bold"),
        )
        self._badge.pack(side="left")

        self._trend = ttk.Label(head, text="", style="MetricTrend.TLabel")
        self._trend.pack(side="right", pady=(6, 0))

        self._value = ttk.Label(self.body, text="0", style="MetricValue.TLabel")
        self._value.pack(anchor="w", pady=(14, 0))
        self._label = ttk.Label(
            self.body, text=label.upper(), style="MetricLabel.TLabel"
        )
        self._label.pack(anchor="w", pady=(2, 0))
        self._detail = ttk.Label(
            self.body, text="", style="MetricDetail.TLabel",
            wraplength=200, justify="left",
        )
        self._detail.pack(anchor="w", pady=(8, 0))

        # The sparkline bleeds to the tile's edges instead of sitting in a box.
        self._spark = tk.Canvas(
            self, height=SPARK_HEIGHT, background=self.fill,
            highlightthickness=0, borderwidth=0,
        )
        self.bind_children()
        # The sparkline is placed over the tile's foot, so the body reserves
        # that band rather than having its last caption drawn through.
        self.fit_height(SPARK_HEIGHT)

    def update_value(
        self, value: object, detail: str = "", *, accent: str = ""
    ) -> None:
        """Show a figure and the line that qualifies it."""
        self._value.configure(text=str(value))
        self._detail.configure(text=detail)
        if accent and accent != self._colour:
            self._recolour(accent)

    def update_sparkline(self, series: list[float]) -> None:
        """Plot the stored series the figure was taken from."""
        self._series = [float(point) for point in series if point is not None]
        self._draw_spark()

    def update_trend(self, current: float, previous: float | None) -> None:
        """Compare against an earlier period, when one is actually stored.

        With nothing to compare against the trend area stays empty rather than
        implying a direction (§1).
        """
        if previous is None or previous <= 0:
            self._trend.configure(text="")
            return
        change = ((current - previous) / previous) * 100.0
        rising = change >= 0
        self._trend.configure(
            text=f"{'▲' if rising else '▼'}{abs(change):,.0f}%",
            foreground=PALETTE.ok if not rising else PALETTE.high,
        )

    def _recolour(self, colour: str) -> None:
        """Repaint the badge and the sparkline in a new severity colour."""
        self._colour = colour
        self._badge.delete("all")
        rounded_rectangle(
            self._badge, 0, 0, 34, 34, 10,
            fill=blend(self.fill, colour, 0.20), outline="",
        )
        self._badge.create_text(
            17, 17, text=self._glyph, fill=colour,
            font=(self._fonts.family if self._fonts else "TkDefaultFont", 14, "bold"),
        )
        self._draw_spark()

    def _draw_spark(self) -> None:
        """Paint the trend line across the foot of the tile."""
        self._spark.delete("all")
        width = max(int(self.winfo_width()), 1)
        height = SPARK_HEIGHT
        if len(self._series) < 2 or width < 8:
            return
        self._spark.place(x=0, y=max(0, self.winfo_height() - height - SHADOW_DEPTH))
        self._spark.configure(width=width)
        lowest, highest = min(self._series), max(self._series)
        span = (highest - lowest) or 1.0
        step = width / (len(self._series) - 1)
        points: list[float] = []
        for index, point in enumerate(self._series):
            points.append(index * step)
            points.append(height - 4 - ((point - lowest) / span) * (height - 10))
        # A filled area under the line: a bare polyline reads as a chart that
        # escaped from a panel; a soft fill reads as part of the tile.
        area = [*points, width, height, 0.0, float(height)]
        self._spark.create_polygon(
            area, fill=blend(self.fill, self._colour, 0.14), outline="",
        )
        self._spark.create_line(
            *points, fill=self._colour, width=2, smooth=True,
        )
