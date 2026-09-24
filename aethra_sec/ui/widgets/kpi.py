"""A dense band of headline figures (§9).

This replaces the metric *card*. Six tiles, each an elevated surface with a
badge, a display-size number, a caption, a detail line and a bled sparkline,
occupied two rows and roughly a third of the dashboard before a single real
record was shown. The figures were large but the screen answered "what needs
my attention?" slowly, because the answer was below the fold.

A KPI strip is one continuous band. Cells are separated by a hairline rather
than boxed individually, each carries a colour edge that means severity, and
the whole row costs about the height of one previous tile. Everything else on
the page moves up by that much.

``0`` is still rendered as ``0``. A genuine zero is information on a
monitoring console, and hiding it would make the strip less honest rather than
more compact (§72).
"""

from __future__ import annotations

import tkinter as tk
from dataclasses import dataclass
from tkinter import ttk
from typing import Any, Callable

from aethra_sec.ui.theme import METRICS, PALETTE, Fonts
from aethra_sec.ui.widgets.tooltip import attach_tooltip

#: Narrowest a cell may be before the strip wraps to another line.
MIN_CELL_WIDTH = 150


@dataclass(frozen=True)
class Kpi:
    """One figure in a :class:`KpiStrip`."""

    key: str
    label: str
    colour: str = ""
    #: Opened when the cell is clicked. Only ever a screen that exists.
    on_click: Callable[[], None] | None = None
    tooltip: str = ""


class _KpiCell(ttk.Frame):
    """One figure: a colour edge, a label, a value, and a qualifying line."""

    def __init__(self, parent: tk.Misc, kpi: Kpi, fonts: Fonts | None) -> None:
        """Build an empty cell; :meth:`update_value` fills it in."""
        super().__init__(parent, style="Card.TFrame")
        self._colour = kpi.colour or PALETTE.accent
        self._fonts = fonts

        # The edge carries the severity meaning that a badge used to, in a
        # fraction of the space and without competing with the figure.
        self._edge = tk.Frame(self, background=self._colour, width=2)
        self._edge.pack(side="left", fill="y")

        body = ttk.Frame(self, style="Card.TFrame", padding=(10, 6, 12, 6))
        body.pack(side="left", fill="both", expand=True)

        self._label = ttk.Label(
            body, text=kpi.label.upper(), style="CardTitle.TLabel"
        )
        self._label.pack(anchor="w")

        figure = ttk.Frame(body, style="Card.TFrame")
        figure.pack(fill="x", pady=(1, 0))
        self._value = ttk.Label(figure, text="-", style="KpiValue.TLabel")
        self._value.pack(side="left")
        self._trend = ttk.Label(figure, text="", style="KpiTrend.TLabel")
        self._trend.pack(side="left", padx=(6, 0), pady=(4, 0))

        # One line, never wrapped: a strip stays a strip. The full text is on
        # the tooltip, so nothing is lost by not wrapping it here.
        self._detail = ttk.Label(body, text="", style="CardDim.TLabel", anchor="w")
        self._detail.pack(anchor="w", fill="x")

        self._widgets = (self, body, figure, self._label, self._value,
                         self._trend, self._detail)
        if kpi.on_click is not None:
            for widget in self._widgets:
                widget.bind("<Button-1>", lambda _e, f=kpi.on_click: f())
                widget.configure(cursor="hand2")
            self.bind("<Enter>", self._on_enter, add="+")
            self.bind("<Leave>", self._on_leave, add="+")
        if kpi.tooltip:
            attach_tooltip(self, kpi.tooltip)

    def _on_enter(self, _event: tk.Event) -> None:
        """Lift the cell while the pointer is over it."""
        self._set_style("CardHover.TFrame", "CardHover.TLabel")

    def _on_leave(self, _event: tk.Event) -> None:
        """Return to the page ground."""
        self._set_style("Card.TFrame", "Card.TLabel")

    def _set_style(self, frame_style: str, _label_style: str) -> None:
        """Swap the cell's surface without disturbing the label styles."""
        for widget in self._widgets:
            try:
                if isinstance(widget, ttk.Frame):
                    widget.configure(style=frame_style)
            except tk.TclError:  # pragma: no cover - torn down
                return

    def update_value(
        self, value: object, detail: str = "", *, accent: str = ""
    ) -> None:
        """Show a figure and the line that qualifies it."""
        self._value.configure(text=str(value))
        self._detail.configure(text=detail)
        if accent and accent != self._colour:
            self._colour = accent
            try:
                self._edge.configure(background=accent)
            except tk.TclError:  # pragma: no cover - torn down
                pass

    def update_label(self, label: str) -> None:
        """Retitle the cell.

        A figure counted over a reporting window has to say which window, and
        the answer changes - at midnight, and whenever the operator selects a
        different period. A caption that still reads "today" while the page
        reports on yesterday is worse than no caption.
        """
        self._label.configure(text=str(label).upper())

    def update_trend(self, current: float, previous: float | None) -> None:
        """Show the change against a comparable earlier period.

        ``previous`` of ``None`` means no comparable period is stored, and the
        cell then shows nothing rather than a fabricated 0%.
        """
        if previous is None:
            self._trend.configure(text="", foreground=PALETTE.text_dim)
            return
        delta = current - previous
        if abs(delta) < 1e-9:
            self._trend.configure(text="—", foreground=PALETTE.text_dim)
            return
        arrow = "▲" if delta > 0 else "▼"
        magnitude = (
            f"{abs(delta / previous * 100):.0f}%" if previous else f"{abs(delta):.0f}"
        )
        self._trend.configure(
            text=f"{arrow}{magnitude}",
            foreground=PALETTE.medium if delta > 0 else PALETTE.low,
        )

    # The strip carries no sparkline: a trend arrow answers "which way" in a
    # tenth of the space, and the shape over time is on the traffic chart
    # directly below. Kept so existing callers do not have to branch.
    def update_sparkline(self, _values: object) -> None:
        """Accepted and ignored - the strip shows direction, not shape."""


class KpiStrip(ttk.Frame):
    """A row of figures, divided by hairlines rather than boxed."""

    def __init__(
        self, parent: tk.Misc, kpis: list[Kpi], *, fonts: Fonts | None = None
    ) -> None:
        """Build the strip and lay it out for the current width."""
        super().__init__(parent, style="Card.TFrame")
        self._cells: dict[str, _KpiCell] = {}
        self._order: list[str] = []
        self._dividers: list[tk.Frame] = []
        self._columns = 0

        for kpi in kpis:
            self._cells[kpi.key] = _KpiCell(self, kpi, fonts)
            self._order.append(kpi.key)

        self._layout(len(self._order))
        self.bind("<Configure>", self._on_configure)

    def __getitem__(self, key: str) -> _KpiCell:
        """The cell for a key, so a screen can update one figure."""
        return self._cells[key]

    def get(self, key: str) -> _KpiCell | None:
        """The cell for a key, or ``None`` when it is not in the strip."""
        return self._cells.get(key)

    def update_counts(self, counts: dict[str, Any]) -> None:
        """Set several figures at once from a key -> value mapping.

        The signature :class:`SummaryStrip` used, so a screen that reported a
        row of counts migrates to the strip without rewriting how it feeds it.
        A key the strip does not carry is ignored; a key it carries but the
        mapping omits is cleared to ``-`` rather than left showing a stale
        figure from the previous refresh.
        """
        for key, cell in self._cells.items():
            if key not in counts:
                cell.update_value("-")
                continue
            value = counts[key]
            cell.update_value(f"{value:,}" if isinstance(value, int) else str(value))

    def _on_configure(self, event: tk.Event) -> None:
        """Re-flow when the window width changes.

        Six figures do not fit on a narrow window, and squeezing them until a
        number clips defeats the point of a headline metric.
        """
        fits = max(1, min(len(self._order), int(event.width) // MIN_CELL_WIDTH))
        self._layout(fits)

    def _layout(self, columns: int) -> None:
        """Grid the cells into ``columns`` per line, with dividers between."""
        columns = max(1, columns)
        if columns == self._columns or not self._order:
            return
        self._columns = columns

        for divider in self._dividers:
            divider.destroy()
        self._dividers.clear()
        for index in range(len(self._order) * 2):
            self.columnconfigure(index, weight=0, uniform="")

        for index, key in enumerate(self._order):
            line, column = divmod(index, columns)
            grid_column = column * 2
            self._cells[key].grid(
                row=line, column=grid_column, sticky="nsew",
                pady=(0 if line == 0 else METRICS.space_sm, 0),
            )
            # A hairline between neighbours replaces the gap between cards:
            # the figures read as one instrument rather than six objects.
            if column < columns - 1 and index < len(self._order) - 1:
                divider = tk.Frame(self, background=PALETTE.border, width=1)
                divider.grid(row=line, column=grid_column + 1, sticky="ns",
                             pady=METRICS.space_xs)
                self._dividers.append(divider)

        for column in range(columns):
            self.columnconfigure(column * 2, weight=1, uniform="kpi")
