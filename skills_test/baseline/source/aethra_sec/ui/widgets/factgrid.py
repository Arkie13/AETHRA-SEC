"""Responsive fact grid for detail panels (§44).

A two-column list of ``label: value`` rows reads as prose - every line the same
weight, the eye with nowhere to land - and it is twice as tall as it needs to
be, which is what forced a detail panel to scroll inside itself.

This lays the same facts out as a grid of small cells: a short muted label
above a brighter value. Column count follows the real width, so the grid is one
column when the panel is narrow and never overflows horizontally.

Nothing here formats or derives a value. Callers pass the strings they already
had; this only arranges them.
"""

from __future__ import annotations

import tkinter as tk
from collections.abc import Sequence
from tkinter import ttk
from typing import Any

from aethra_sec.ui.theme import METRICS, PALETTE, Fonts

#: Width one cell needs before a second column is worth having.
MIN_CELL_WIDTH = 240

#: Never exceed this many columns, however wide the panel gets - facts spread
#: across five columns stop reading as pairs.
MAX_COLUMNS = 3


class Fact:
    """One labelled value.

    Attributes:
        label: the short caption, shown small and muted.
        value: the value itself, shown brighter.
        colour: optional explicit value colour, for a fact that carries
            meaning of its own (a trusted asset, say).
        span: True to give the fact the full row - used for a long value that
            would otherwise wrap badly in a narrow cell.
    """

    __slots__ = ("label", "value", "colour", "span")

    def __init__(
        self,
        label: str,
        value: str,
        *,
        colour: str = "",
        span: bool = False,
    ) -> None:
        self.label = label
        self.value = value
        self.colour = colour
        self.span = span


class FactGrid(ttk.Frame):
    """Facts as a responsive grid of label-over-value cells."""

    def __init__(
        self,
        parent: tk.Misc,
        *,
        fonts: Fonts | None = None,
        surface: str = "",
    ) -> None:
        """Create an empty grid; call :meth:`set_facts` to fill it."""
        super().__init__(parent, style="Card.TFrame")
        self._fonts = fonts
        self._surface = surface or PALETTE.surface
        self._facts: list[Fact] = []
        self._columns = 0
        self._cells: list[tuple[ttk.Frame, Fact]] = []
        self._grid = ttk.Frame(self, style="Card.TFrame")
        self._grid.pack(fill="x")
        #: A qualifier under the grid, for a fact that needs one sentence more
        #: than its cell can hold. Hidden when empty.
        self._note = ttk.Label(
            self, text="", style="CardDim.TLabel", justify="left"
        )
        self.bind("<Configure>", self._on_configure, add="+")

    # ------------------------------------------------------------------
    def set_facts(self, facts: Sequence[Fact]) -> None:
        """Replace the displayed facts."""
        self._facts = [f for f in facts if f is not None]
        self._columns = 0  # force a rebuild even at the same width
        self._render()

    # ------------------------------------------------------------------
    def set_note(self, text: str) -> None:
        """Show a qualifying sentence under the grid, or hide it when empty."""
        if text:
            self._note.configure(text=text)
            self._note.pack(anchor="w", pady=(METRICS.space_xs, 0))
        else:
            self._note.pack_forget()

    def _column_count(self) -> int:
        """How many columns the current width supports."""
        width = self.winfo_width()
        if width <= 1:
            # Before the first layout pass, assume the common case rather than
            # rendering a one-column grid that immediately reflows.
            return 2
        return max(1, min(MAX_COLUMNS, width // MIN_CELL_WIDTH))

    def _on_configure(self, _event: tk.Event | None = None) -> None:
        """Re-flow when the panel width changes the column count."""
        if self._facts and self._column_count() != self._columns:
            self._render()

    def _render(self) -> None:
        """Lay the facts out at the current column count."""
        for child in self._grid.winfo_children():
            child.destroy()
        self._cells.clear()

        columns = self._column_count()
        self._columns = columns
        for index in range(columns):
            self._grid.columnconfigure(index, weight=1, uniform="fact")

        row = 0
        column = 0
        for fact in self._facts:
            span = columns if fact.span else 1
            if fact.span and column:
                # A full-width fact starts its own row.
                row += 1
                column = 0

            cell = self._cell(fact)
            cell.grid(
                row=row,
                column=column,
                columnspan=span,
                sticky="ew",
                padx=(0, METRICS.space_lg if span == 1 else 0),
                pady=(0, METRICS.space_md),
            )
            self._cells.append((cell, fact))

            column += span
            if column >= columns:
                row += 1
                column = 0

    def _cell(self, fact: Fact) -> ttk.Frame:
        """One label-over-value cell."""
        cell = ttk.Frame(self._grid, style="Card.TFrame")

        ttk.Label(
            cell,
            text=fact.label.upper(),
            style="CardDim.TLabel",
        ).pack(anchor="w")

        value = ttk.Label(
            cell,
            text=fact.value or "-",
            style="Card.TLabel",
            justify="left",
        )
        if fact.colour:
            value.configure(foreground=fact.colour)
        if self._fonts is not None:
            value.configure(font=self._fonts.body_bold)
        value.pack(anchor="w")

        # A long value wraps inside its own cell rather than widening the grid.
        def rewrap(event: tk.Event, label: ttk.Label = value) -> None:
            label.configure(wraplength=max(120, event.width - 4))

        cell.bind("<Configure>", rewrap, add="+")
        return cell
