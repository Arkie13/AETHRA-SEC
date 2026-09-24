"""Detail panel layout (§44).

The panel used to be a header, a title and a scrollbar: stacked under the
queue it inherited about 250px of a 490px split while its content needed six
times that. These pin the pieces of the redesign that keep it readable.
"""

from __future__ import annotations

import tkinter as tk

import pytest

from aethra_sec.ui.theme import apply_theme
from aethra_sec.ui.widgets.cards import ScrollableFrame
from aethra_sec.ui.widgets.factgrid import (
    MAX_COLUMNS,
    MIN_CELL_WIDTH,
    Fact,
    FactGrid,
)


@pytest.fixture()
def root():
    """A real Tk root, skipped where no display is available."""
    try:
        window = tk.Tk()
    except tk.TclError:  # pragma: no cover - headless CI
        pytest.skip("no display available")
    window.geometry("1200x800")
    apply_theme(window)
    yield window
    window.destroy()


def settle(widget: tk.Misc, times: int = 6) -> None:
    """Let Tk finish laying out."""
    for _ in range(times):
        widget.update_idletasks()
        widget.update()


class TestFactGridLayout:
    """Facts are a responsive grid, not a column of prose."""

    def test_it_uses_more_columns_when_it_has_the_width(self, root) -> None:
        grid = FactGrid(root)
        grid.pack(fill="x")
        grid.configure(width=MIN_CELL_WIDTH * 3)
        settle(root)
        grid.set_facts([Fact(f"L{i}", f"V{i}") for i in range(6)])
        settle(root)
        assert grid._columns >= 2  # noqa: SLF001

    def test_it_collapses_to_one_column_when_narrow(self, root) -> None:
        """A narrow panel must reflow, not overflow horizontally."""
        holder = tk.Frame(root, width=MIN_CELL_WIDTH - 40, height=400)
        holder.pack_propagate(False)
        holder.pack()
        grid = FactGrid(holder)
        grid.pack(fill="x")
        settle(root)
        grid.set_facts([Fact(f"L{i}", f"V{i}") for i in range(4)])
        settle(root)
        assert grid._columns == 1  # noqa: SLF001

    def test_it_never_spreads_beyond_the_column_cap(self, root) -> None:
        """Facts across five columns stop reading as label/value pairs."""
        grid = FactGrid(root)
        grid.pack(fill="x")
        grid.configure(width=MIN_CELL_WIDTH * 12)
        settle(root)
        grid.set_facts([Fact(f"L{i}", f"V{i}") for i in range(12)])
        settle(root)
        assert grid._columns <= MAX_COLUMNS  # noqa: SLF001

    def test_a_spanning_fact_takes_the_whole_row(self, root) -> None:
        grid = FactGrid(root)
        grid.pack(fill="x")
        grid.configure(width=MIN_CELL_WIDTH * 2)
        settle(root)
        grid.set_facts(
            [Fact("A", "1"), Fact("Long", "value", span=True), Fact("B", "2")]
        )
        settle(root)
        spans = [
            cell.grid_info().get("columnspan", 1)
            for cell, fact in grid._cells  # noqa: SLF001
            if fact.span
        ]
        assert spans and all(int(s) == grid._columns for s in spans)  # noqa: SLF001

    def test_the_grid_shows_what_it_is_given(self, root) -> None:
        """It arranges values; it never derives or reformats them."""
        grid = FactGrid(root)
        grid.pack(fill="x")
        settle(root)
        grid.set_facts([Fact("Source", "192.168.1.7")])
        settle(root)
        shown = [
            child.cget("text")
            for cell, _fact in grid._cells  # noqa: SLF001
            for child in cell.winfo_children()
        ]
        assert "192.168.1.7" in shown
        # The label is capitalised for the caption style, nothing more.
        assert "SOURCE" in shown

    def test_an_empty_value_renders_a_dash_not_a_blank(self, root) -> None:
        grid = FactGrid(root)
        grid.pack(fill="x")
        settle(root)
        grid.set_facts([Fact("Destination", "")])
        settle(root)
        shown = [
            child.cget("text")
            for cell, _fact in grid._cells  # noqa: SLF001
            for child in cell.winfo_children()
        ]
        assert "-" in shown


class TestScrollbarAppearsOnlyWhenNeeded:
    """No scrollbar track beside content that fits."""

    def test_short_content_shows_no_scrollbar(self, root) -> None:
        scroller = ScrollableFrame(root, autohide=True)
        scroller.pack(fill="both", expand=True)
        tk.Label(scroller.interior, text="one short line").pack()
        settle(root, times=10)
        assert not scroller._scrollbar.winfo_ismapped()  # noqa: SLF001

    def test_long_content_shows_the_scrollbar(self, root) -> None:
        scroller = ScrollableFrame(root, autohide=True)
        scroller.pack(fill="both", expand=True)
        for index in range(200):
            tk.Label(scroller.interior, text=f"row {index}").pack()
        settle(root, times=10)
        assert scroller._scrollbar.winfo_ismapped()  # noqa: SLF001

    def test_hiding_is_opt_in(self, root) -> None:
        """A host too narrow to yield the width later needs it reserved.

        The sidebar is that host: a canvas asks for far more width than it has,
        so its scrollbar is packed up front and stays.
        """
        scroller = ScrollableFrame(root)
        scroller.pack(fill="both", expand=True)
        tk.Label(scroller.interior, text="short").pack()
        settle(root, times=10)
        assert scroller._scrollbar.winfo_ismapped()  # noqa: SLF001
