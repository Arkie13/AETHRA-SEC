"""Charts drawn directly on a Tkinter ``Canvas`` (§51).

Charts are hand-drawn rather than delegated to a plotting library: it keeps the
dependency surface to the standard library, redraws fast enough for a 1-second
dashboard tick, and - most importantly here - lets each chart render an honest
empty state instead of an axis frame implying data that does not exist.

Every chart therefore has two modes: it either plots real measurements, or it
says there are not enough of them yet.
"""

from __future__ import annotations

import tkinter as tk
from dataclasses import dataclass
from datetime import datetime
from typing import Callable, Sequence

from aethra_sec.ui.theme import PALETTE, severity_colour
from aethra_sec.utils.formatting import format_bytes, format_count
from aethra_sec.utils.timeutil import to_local

#: Minimum points before a time-series chart will draw a line.
MIN_SERIES_POINTS = 2


class BaseChart(tk.Canvas):
    """Shared drawing helpers and empty-state handling."""

    def __init__(
        self,
        parent: tk.Misc,
        *,
        height: int = 160,
        empty_message: str = "No data available",
        empty_detail: str = "",
        padding: tuple[int, int, int, int] = (46, 12, 12, 24),
    ) -> None:
        """Create an empty chart canvas."""
        super().__init__(
            parent,
            height=height,
            background=PALETTE.surface,
            highlightthickness=0,
            borderwidth=0,
        )
        self._empty_message = empty_message
        self._empty_detail = empty_detail
        self._padding = padding
        self._has_data = False
        self.bind("<Configure>", lambda _event: self.redraw())

    @property
    def has_data(self) -> bool:
        """True when the chart is showing real measurements."""
        return self._has_data

    def set_empty_message(self, message: str, detail: str = "") -> None:
        """Change the text shown when there is nothing to plot."""
        self._empty_message = message
        self._empty_detail = detail
        if not self._has_data:
            self.redraw()

    def redraw(self) -> None:
        """Repaint the chart (overridden by subclasses)."""
        self.delete("all")
        self._draw_empty()

    def _plot_area(self) -> tuple[int, int, int, int]:
        """``(left, top, right, bottom)`` of the plotting rectangle."""
        left, top, right, bottom = self._padding
        width = max(int(self.winfo_width()), 200)
        height = max(int(self.winfo_height()), 80)
        return left, top, width - right, height - bottom

    def _draw_empty(self) -> None:
        """Render the empty state."""
        width = max(int(self.winfo_width()), 200)
        height = max(int(self.winfo_height()), 80)
        self.create_text(
            width / 2, height / 2 - (8 if self._empty_detail else 0),
            text=self._empty_message, fill=PALETTE.text_muted,
            font=("TkDefaultFont", 10),
        )
        if self._empty_detail:
            self.create_text(
                width / 2, height / 2 + 12, text=self._empty_detail,
                fill=PALETTE.text_dim, font=("TkDefaultFont", 8),
                width=max(160, width - 40),
            )

    def _draw_grid(
        self, maximum: float, *, lines: int = 4, formatter=format_count
    ) -> None:
        """Draw horizontal grid lines with value labels."""
        left, top, right, bottom = self._plot_area()
        if right <= left or bottom <= top:
            return
        for index in range(lines + 1):
            ratio = index / lines
            y = bottom - (bottom - top) * ratio
            self.create_line(left, y, right, y, fill=PALETTE.grid, width=1)
            value = maximum * ratio
            self.create_text(
                left - 6, y, text=formatter(value), anchor="e",
                fill=PALETTE.text_dim, font=("TkDefaultFont", 7),
            )

    # ------------------------------------------------------------------
    # Hover readout
    # ------------------------------------------------------------------
    def _draw_readout(self, x: float, y: float, lines: Sequence[str]) -> None:
        """Draw a small value box near ``(x, y)``, kept inside the canvas.

        The readout states the measurement under the pointer. It is drawn from
        the same values the chart plotted, so hovering can never show a figure
        the chart did not receive.
        """
        if not lines:
            return
        width = max(int(self.winfo_width()), 200)
        height = max(int(self.winfo_height()), 80)
        text = "\n".join(lines)
        box_width = 12 + 6.4 * max(len(line) for line in lines)
        box_height = 10 + 13 * len(lines)

        box_x = x + 12
        if box_x + box_width > width - 4:
            box_x = x - 12 - box_width
        box_x = max(4.0, box_x)
        box_y = max(4.0, min(y - box_height / 2, height - box_height - 4))

        self.create_rectangle(
            box_x, box_y, box_x + box_width, box_y + box_height,
            fill=PALETTE.surface_raised, outline=PALETTE.border_strong,
            tags="readout",
        )
        self.create_text(
            box_x + 6, box_y + 5, text=text, anchor="nw", fill=PALETTE.text,
            font=("TkDefaultFont", 7), tags="readout",
        )


class TimeSeriesChart(BaseChart):
    """A filled line chart over real timestamps (traffic rate, alert rate)."""

    def __init__(
        self,
        parent: tk.Misc,
        *,
        height: int = 160,
        colour: str = PALETTE.accent,
        empty_message: str = "Waiting for live network data...",
        empty_detail: str = "",
        value_formatter=format_count,
        fill: bool = True,
        series_label: str = "value",
    ) -> None:
        """Create the chart."""
        super().__init__(
            parent, height=height, empty_message=empty_message,
            empty_detail=empty_detail,
        )
        self._points: list[tuple[datetime, float]] = []
        self._colour = colour
        self._formatter = value_formatter
        self._fill = fill
        self._series_label = series_label
        self._hover_index: int | None = None

        self.bind("<Motion>", self._on_motion)
        self.bind("<Leave>", self._on_leave)

    def set_points(self, points: Sequence[tuple[datetime, float]]) -> None:
        """Supply real measurements and redraw."""
        self._points = [(stamp, float(value)) for stamp, value in points if stamp]
        self._has_data = len(self._points) >= MIN_SERIES_POINTS
        if self._hover_index is not None and self._hover_index >= len(self._points):
            self._hover_index = None
        self.redraw()

    # ------------------------------------------------------------------
    # Hover
    # ------------------------------------------------------------------
    def _on_motion(self, event: tk.Event) -> None:
        """Track the nearest sample under the pointer."""
        if not self._has_data:
            return
        left, _top, right, _bottom = self._plot_area()
        if right <= left:
            return
        span = max(1, len(self._points) - 1)
        ratio = (event.x - left) / (right - left)
        index = int(round(ratio * span))
        index = max(0, min(len(self._points) - 1, index))
        if index != self._hover_index:
            self._hover_index = index
            self.redraw()

    def _on_leave(self, _event: tk.Event) -> None:
        """Drop the crosshair when the pointer leaves."""
        if self._hover_index is not None:
            self._hover_index = None
            self.redraw()

    def redraw(self) -> None:
        """Repaint the series."""
        self.delete("all")
        if not self._has_data:
            self._draw_empty()
            return

        left, top, right, bottom = self._plot_area()
        if right <= left or bottom <= top:
            return

        values = [value for _, value in self._points]
        maximum = max(values) or 1.0
        maximum = maximum * 1.15
        self._draw_grid(maximum, formatter=self._formatter)

        span = max(1, len(self._points) - 1)
        coordinates: list[float] = []
        for index, (_stamp, value) in enumerate(self._points):
            x = left + (right - left) * (index / span)
            y = bottom - (bottom - top) * (value / maximum)
            coordinates.extend([x, y])

        if self._fill:
            polygon = [left, bottom, *coordinates, right, bottom]
            self.create_polygon(
                polygon, fill=self._colour, outline="", stipple="gray25"
            )
        self.create_line(coordinates, fill=self._colour, width=2, smooth=False)

        peak = max(values)
        peak_index = values.index(peak)
        peak_x = left + (right - left) * (peak_index / span)
        peak_y = bottom - (bottom - top) * (peak / maximum)
        self.create_oval(
            peak_x - 3, peak_y - 3, peak_x + 3, peak_y + 3,
            fill=self._colour, outline=PALETTE.surface,
        )

        first_local = to_local(self._points[0][0])
        last_local = to_local(self._points[-1][0])
        if first_local:
            self.create_text(
                left, bottom + 10, text=first_local.strftime("%H:%M:%S"),
                anchor="w", fill=PALETTE.text_dim, font=("TkDefaultFont", 7),
            )
        if last_local:
            self.create_text(
                right, bottom + 10, text=last_local.strftime("%H:%M:%S"),
                anchor="e", fill=PALETTE.text_dim, font=("TkDefaultFont", 7),
            )
        self.create_text(
            right, top + 6, text=f"peak {self._formatter(peak)}", anchor="e",
            fill=PALETTE.text_muted, font=("TkDefaultFont", 7),
        )

        if self._hover_index is not None and self._hover_index < len(self._points):
            stamp, value = self._points[self._hover_index]
            x = left + (right - left) * (self._hover_index / span)
            y = bottom - (bottom - top) * (value / maximum)
            self.create_line(x, top, x, bottom, fill=PALETTE.border_strong, width=1)
            self.create_oval(
                x - 4, y - 4, x + 4, y + 4, fill=PALETTE.surface,
                outline=self._colour, width=2,
            )
            local = to_local(stamp)
            self._draw_readout(
                x, y,
                [
                    local.strftime("%H:%M:%S") if local else "unknown time",
                    f"{self._series_label}: {self._formatter(value)}",
                ],
            )


class BarChart(BaseChart):
    """A horizontal bar chart for rankings (top talkers, ports, categories)."""

    def __init__(
        self,
        parent: tk.Misc,
        *,
        height: int = 180,
        empty_message: str = "No data available",
        empty_detail: str = "",
        colour_by_severity: bool = False,
        value_formatter=format_count,
        max_bars: int = 8,
        on_select: Callable[[str], None] | None = None,
    ) -> None:
        """Create the chart.

        Args:
            on_select: called with the bar's label when it is clicked, which is
                how the ranking charts drill down into the matching records.
        """
        super().__init__(
            parent, height=height, empty_message=empty_message,
            empty_detail=empty_detail, padding=(4, 8, 12, 8),
        )
        self._items: list[tuple[str, float]] = []
        self._colour_by_severity = colour_by_severity
        self._formatter = value_formatter
        self._max_bars = max_bars
        self._on_select = on_select
        self._hover_index: int | None = None
        self._slot = 16.0

        self.bind("<Motion>", self._on_motion)
        self.bind("<Leave>", self._on_leave)
        if on_select is not None:
            self.bind("<Button-1>", self._on_click)

    def set_items(self, items: Sequence[tuple[str, float]]) -> None:
        """Supply real ``(label, value)`` pairs and redraw."""
        self._items = [
            (str(label), float(value)) for label, value in items if value is not None
        ][: self._max_bars]
        self._has_data = bool(self._items) and any(v > 0 for _, v in self._items)
        if self._hover_index is not None and self._hover_index >= len(self._items):
            self._hover_index = None
        self.redraw()

    # ------------------------------------------------------------------
    # Hover and selection
    # ------------------------------------------------------------------
    def _index_at(self, y: float) -> int | None:
        """Bar index under a vertical position, if any."""
        if not self._items:
            return None
        index = int((y - 6) // self._slot)
        return index if 0 <= index < len(self._items) else None

    def _on_motion(self, event: tk.Event) -> None:
        """Highlight the bar under the pointer."""
        if not self._has_data:
            return
        index = self._index_at(event.y)
        if index != self._hover_index:
            self._hover_index = index
            self.configure(cursor="hand2" if (index is not None and self._on_select) else "")
            self.redraw()

    def _on_leave(self, _event: tk.Event) -> None:
        """Clear the highlight."""
        if self._hover_index is not None:
            self._hover_index = None
            self.redraw()

    def _on_click(self, event: tk.Event) -> None:
        """Report the clicked bar's label."""
        index = self._index_at(event.y)
        if index is not None and self._on_select is not None:
            self._on_select(self._items[index][0])

    def redraw(self) -> None:
        """Repaint the bars."""
        self.delete("all")
        if not self._has_data:
            self._draw_empty()
            return

        width = max(int(self.winfo_width()), 220)
        height = max(int(self.winfo_height()), 80)
        label_width = min(150, max(80, int(width * 0.34)))
        value_width = 62
        bar_left = label_width + 8
        bar_right = width - value_width
        maximum = max(value for _, value in self._items) or 1.0

        count = len(self._items)
        slot = max(16, (height - 8) // max(1, count))
        self._slot = float(slot)
        bar_height = max(8, min(18, slot - 6))
        total = sum(value for _, value in self._items)

        for index, (label, value) in enumerate(self._items):
            y = 6 + index * slot + slot / 2
            hovered = index == self._hover_index
            if hovered:
                self.create_rectangle(
                    0, y - slot / 2, width, y + slot / 2,
                    fill=PALETTE.surface_hover, outline="",
                )
            self.create_text(
                label_width, y, text=label[:28], anchor="e",
                fill=PALETTE.text if hovered else PALETTE.text_muted,
                font=("TkDefaultFont", 8),
            )
            self.create_rectangle(
                bar_left, y - bar_height / 2, bar_right, y + bar_height / 2,
                fill=PALETTE.surface_alt, outline="",
            )
            length = (bar_right - bar_left) * (value / maximum)
            colour = (
                severity_colour(label)
                if self._colour_by_severity
                else PALETTE.series[index % len(PALETTE.series)]
            )
            if length > 1:
                self.create_rectangle(
                    bar_left, y - bar_height / 2, bar_left + length,
                    y + bar_height / 2, fill=colour, outline="",
                )
            self.create_text(
                width - 6, y, text=self._formatter(value), anchor="e",
                fill=PALETTE.text, font=("TkDefaultFont", 8),
            )

        if self._hover_index is not None and self._hover_index < len(self._items):
            label, value = self._items[self._hover_index]
            share = (value / total * 100) if total else 0.0
            y = 6 + self._hover_index * slot + slot / 2
            lines = [label[:36], f"{self._formatter(value)}  ({share:.1f}% of shown)"]
            if self._on_select is not None:
                lines.append("click to filter")
            self._draw_readout(bar_left + 20, y, lines)


class DonutChart(BaseChart):
    """A donut chart for distributions (protocol mix, severity mix)."""

    def __init__(
        self,
        parent: tk.Misc,
        *,
        height: int = 180,
        empty_message: str = "No data available",
        empty_detail: str = "",
        colour_by_severity: bool = False,
        centre_label: str = "",
        on_select: Callable[[str], None] | None = None,
    ) -> None:
        """Create the chart."""
        super().__init__(
            parent, height=height, empty_message=empty_message,
            empty_detail=empty_detail, padding=(8, 8, 8, 8),
        )
        self._items: list[tuple[str, float]] = []
        self._colour_by_severity = colour_by_severity
        self._centre_label = centre_label
        self._on_select = on_select
        self._hover_index: int | None = None
        self._legend_rows: list[tuple[float, float, int]] = []

        self.bind("<Motion>", self._on_motion)
        self.bind("<Leave>", self._on_leave)
        if on_select is not None:
            self.bind("<Button-1>", self._on_click)

    def set_items(self, items: Sequence[tuple[str, float]]) -> None:
        """Supply real ``(label, value)`` pairs and redraw."""
        self._items = [
            (str(label), float(value))
            for label, value in items
            if value and float(value) > 0
        ]
        self._has_data = bool(self._items)
        if self._hover_index is not None and self._hover_index >= len(self._items):
            self._hover_index = None
        self.redraw()

    # ------------------------------------------------------------------
    # Hover and selection
    # ------------------------------------------------------------------
    def _index_at(self, y: float) -> int | None:
        """Legend row index under a vertical position, if any."""
        for top, bottom, index in self._legend_rows:
            if top <= y <= bottom:
                return index
        return None

    def _on_motion(self, event: tk.Event) -> None:
        """Highlight the hovered legend entry and its slice."""
        if not self._has_data:
            return
        index = self._index_at(event.y)
        if index != self._hover_index:
            self._hover_index = index
            self.configure(cursor="hand2" if (index is not None and self._on_select) else "")
            self.redraw()

    def _on_leave(self, _event: tk.Event) -> None:
        """Clear the highlight."""
        if self._hover_index is not None:
            self._hover_index = None
            self.redraw()

    def _on_click(self, event: tk.Event) -> None:
        """Report the clicked legend entry's label."""
        index = self._index_at(event.y)
        if index is not None and self._on_select is not None:
            self._on_select(self._items[index][0])

    def redraw(self) -> None:
        """Repaint the donut and its legend."""
        self.delete("all")
        if not self._has_data:
            self._draw_empty()
            return

        width = max(int(self.winfo_width()), 220)
        height = max(int(self.winfo_height()), 120)
        diameter = min(height - 16, int(width * 0.46))
        left = 12
        top = (height - diameter) / 2
        total = sum(value for _, value in self._items) or 1.0

        start = 90.0
        for index, (label, value) in enumerate(self._items):
            extent = -360.0 * (value / total)
            colour = (
                severity_colour(label)
                if self._colour_by_severity
                else PALETTE.series[index % len(PALETTE.series)]
            )
            hovered = index == self._hover_index
            inset = -4 if hovered else 0
            self.create_arc(
                left + inset, top + inset,
                left + diameter - inset, top + diameter - inset,
                start=start, extent=extent, fill=colour,
                outline=PALETTE.text if hovered else PALETTE.surface,
                width=1, style="pieslice",
            )
            start += extent

        hole = diameter * 0.55
        offset = (diameter - hole) / 2
        self.create_oval(
            left + offset, top + offset, left + offset + hole, top + offset + hole,
            fill=PALETTE.surface, outline="",
        )
        self.create_text(
            left + diameter / 2, top + diameter / 2 - 6,
            text=format_count(int(total)), fill=PALETTE.text,
            font=("TkDefaultFont", 11, "bold"),
        )
        if self._centre_label:
            self.create_text(
                left + diameter / 2, top + diameter / 2 + 10,
                text=self._centre_label, fill=PALETTE.text_dim,
                font=("TkDefaultFont", 7),
            )

        legend_x = left + diameter + 18
        legend_y = max(12, (height - len(self._items) * 18) / 2)
        self._legend_rows = []
        for index, (label, value) in enumerate(self._items[:8]):
            colour = (
                severity_colour(label)
                if self._colour_by_severity
                else PALETTE.series[index % len(PALETTE.series)]
            )
            y = legend_y + index * 18
            hovered = index == self._hover_index
            self._legend_rows.append((y - 4, y + 14, index))
            if hovered:
                self.create_rectangle(
                    legend_x - 6, y - 4, width - 4, y + 14,
                    fill=PALETTE.surface_hover, outline="",
                )
            self.create_rectangle(
                legend_x, y, legend_x + 9, y + 9, fill=colour, outline=""
            )
            share = value / total * 100
            self.create_text(
                legend_x + 15, y + 4,
                text=f"{label[:16]}  {format_count(int(value))}  ({share:.0f}%)",
                anchor="w", fill=PALETTE.text if hovered else PALETTE.text_muted,
                font=("TkDefaultFont", 8),
            )


class TimelineChart(BaseChart):
    """A dotted event timeline used for the threat timeline widget (§9)."""

    @dataclass(frozen=True)
    class Entry:
        """One timeline event."""

        at: datetime
        severity: str
        label: str

    def __init__(
        self,
        parent: tk.Misc,
        *,
        height: int = 110,
        empty_message: str = "No security events recorded",
        empty_detail: str = "",
    ) -> None:
        """Create the timeline."""
        super().__init__(
            parent, height=height, empty_message=empty_message,
            empty_detail=empty_detail, padding=(12, 12, 12, 22),
        )
        self._entries: list[TimelineChart.Entry] = []

    def set_entries(self, entries: Sequence["TimelineChart.Entry"]) -> None:
        """Supply real events and redraw."""
        self._entries = sorted(
            (e for e in entries if e.at is not None), key=lambda e: e.at
        )
        self._has_data = bool(self._entries)
        self.redraw()

    def redraw(self) -> None:
        """Repaint the timeline."""
        self.delete("all")
        if not self._has_data:
            self._draw_empty()
            return

        left, top, right, bottom = self._plot_area()
        axis_y = (top + bottom) / 2
        self.create_line(left, axis_y, right, axis_y, fill=PALETTE.grid, width=2)

        first = self._entries[0].at
        last = self._entries[-1].at
        span = max(1.0, (last - first).total_seconds())

        for index, entry in enumerate(self._entries):
            ratio = (entry.at - first).total_seconds() / span
            x = left + (right - left) * ratio
            colour = severity_colour(entry.severity)
            above = index % 2 == 0
            tick_y = axis_y - 14 if above else axis_y + 14
            self.create_line(x, axis_y, x, tick_y, fill=colour, width=1)
            self.create_oval(x - 4, axis_y - 4, x + 4, axis_y + 4, fill=colour, outline="")
            if len(self._entries) <= 12:
                self.create_text(
                    x, tick_y - 6 if above else tick_y + 6,
                    text=entry.label[:22], fill=PALETTE.text_muted,
                    font=("TkDefaultFont", 7), anchor="s" if above else "n",
                )

        for stamp, x, anchor in (
            (first, left, "w"), (last, right, "e"),
        ):
            local = to_local(stamp)
            if local:
                self.create_text(
                    x, bottom + 8, text=local.strftime("%d %b %H:%M"), anchor=anchor,
                    fill=PALETTE.text_dim, font=("TkDefaultFont", 7),
                )
        self.create_text(
            (left + right) / 2, bottom + 8,
            text=f"{len(self._entries)} event(s)", fill=PALETTE.text_dim,
            font=("TkDefaultFont", 7),
        )


class SparkBar(BaseChart):
    """A compact bar sparkline used inside stat cards."""

    def __init__(
        self, parent: tk.Misc, *, height: int = 34, colour: str = PALETTE.accent
    ) -> None:
        """Create the sparkline."""
        super().__init__(
            parent, height=height, empty_message="", padding=(0, 2, 0, 2)
        )
        self.configure(width=40)  # see Sparkline: do not dictate the tile width
        self._values: list[float] = []
        self._colour = colour

    def set_values(self, values: Sequence[float]) -> None:
        """Supply real values and redraw."""
        self._values = [float(v) for v in values]
        self._has_data = bool(self._values) and any(v > 0 for v in self._values)
        self.redraw()

    def redraw(self) -> None:
        """Repaint the sparkline."""
        self.delete("all")
        if not self._has_data:
            return
        width = max(int(self.winfo_width()), 60)
        height = max(int(self.winfo_height()), 20)
        maximum = max(self._values) or 1.0
        count = len(self._values)
        bar_width = max(1.0, (width - (count - 1)) / count)
        for index, value in enumerate(self._values):
            x = index * (bar_width + 1)
            bar_height = max(1.0, (height - 4) * (value / maximum))
            self.create_rectangle(
                x, height - bar_height - 2, x + bar_width, height - 2,
                fill=self._colour, outline="",
            )


class Sparkline(BaseChart):
    """A tiny filled line chart shown inside a metric tile.

    It plots the same stored measurements the tile's number came from. With
    fewer than two measurements it draws nothing at all - a single point is not
    a trend, and a flat line across an empty period would imply one (§1).
    """

    def __init__(
        self,
        parent: tk.Misc,
        *,
        height: int = 26,
        colour: str = PALETTE.accent,
        value_formatter=format_count,
        label: str = "",
    ) -> None:
        """Create the sparkline."""
        super().__init__(
            parent, height=height, empty_message="", padding=(0, 2, 0, 2)
        )
        # A Canvas asks for 378px by default, which would set the width of the
        # metric tile it sits in. The sparkline stretches with ``fill="x"``, so
        # it only needs to request enough to exist.
        self.configure(width=40)
        self._values: list[float] = []
        self._colour = colour
        self._formatter = value_formatter
        self._label = label
        self._hover_index: int | None = None

        self.bind("<Motion>", self._on_motion)
        self.bind("<Leave>", self._on_leave)

    def set_values(self, values: Sequence[float], colour: str | None = None) -> None:
        """Supply real measurements and redraw."""
        self._values = [float(value) for value in values]
        if colour:
            self._colour = colour
        self._has_data = len(self._values) >= MIN_SERIES_POINTS
        self.redraw()

    def _on_motion(self, event: tk.Event) -> None:
        """Track the sample under the pointer."""
        if not self._has_data:
            return
        width = max(int(self.winfo_width()), 40)
        span = max(1, len(self._values) - 1)
        index = max(0, min(span, int(round(event.x / width * span))))
        if index != self._hover_index:
            self._hover_index = index
            self.redraw()

    def _on_leave(self, _event: tk.Event) -> None:
        """Clear the marker."""
        if self._hover_index is not None:
            self._hover_index = None
            self.redraw()

    def redraw(self) -> None:
        """Repaint the sparkline."""
        self.delete("all")
        if not self._has_data:
            return
        width = max(int(self.winfo_width()), 40)
        height = max(int(self.winfo_height()), 16)
        maximum = max(self._values) or 1.0
        span = max(1, len(self._values) - 1)

        coordinates: list[float] = []
        for index, value in enumerate(self._values):
            x = width * (index / span)
            y = (height - 3) - (height - 6) * (value / maximum)
            coordinates.extend([x, y])

        self.create_polygon(
            [0, height, *coordinates, width, height],
            fill=self._colour, outline="", stipple="gray25",
        )
        self.create_line(coordinates, fill=self._colour, width=1.5)

        if self._hover_index is not None and self._hover_index < len(self._values):
            value = self._values[self._hover_index]
            x = width * (self._hover_index / span)
            y = (height - 3) - (height - 6) * (value / maximum)
            self.create_oval(
                x - 2.5, y - 2.5, x + 2.5, y + 2.5,
                fill=PALETTE.surface, outline=self._colour,
            )
            text = self._formatter(value)
            if self._label:
                text = f"{text} {self._label}"
            self.create_text(
                width, 1, text=text, anchor="ne", fill=PALETTE.text,
                font=("TkDefaultFont", 7),
            )


def bytes_formatter(value: float) -> str:
    """Axis formatter for byte-rate charts."""
    return format_bytes(value)
