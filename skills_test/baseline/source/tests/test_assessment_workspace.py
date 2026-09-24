"""The Vulnerability Assessment workspace: layout, scrolling and refresh cost.

The rendered page had the host table squeezed into a fraction of the window
with two vertical scrollbars down the right edge. The cause was structural: the
tab was wrapped in a scroll host, which sizes its interior to the content's
requested height - so the table's ``expand=True`` could never grow it, and the
whole tab scrolled instead.

These tests pin the fix and the two things that went with it: the verbose scan
diagnostics no longer occupy the space the table needs (they are kept, behind a
disclosure), and the periodic refresh reconciles rows in place instead of
rebuilding the table and dropping the operator's selection.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCREEN = ROOT / "aethra_sec" / "ui" / "screens" / "vulnerabilities.py"
TABLES = ROOT / "aethra_sec" / "ui" / "widgets" / "tables.py"


def _method(path: Path, name: str) -> str:
    """One method's source, docstring stripped."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            body = node.body
            if (
                body
                and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
            ):
                node.body = body[1:] or [ast.Pass()]
            return ast.unparse(node)
    raise AssertionError(f"{name} not found in {path.name}")


class TestTheTableOwnsTheWindow:
    """One scroll region on the page, and it is the table's."""

    def test_the_automation_tab_is_not_a_scroll_host(self) -> None:
        build = _method(SCREEN, "build")
        # The automation tab must be a plain frame: a ScrollableFrame sizes its
        # interior to content, which is what stopped the table expanding.
        automation = build[build.index("automation ="):build.index("notebook.add(automation")]
        assert "ScrollableFrame" not in automation, (
            "the automation tab is wrapped in a scroll host again, so the host "
            "table cannot expand and the page grows a second scrollbar"
        )
        assert "ttk.Frame(notebook" in automation

    def test_the_table_is_told_to_fill_its_tab(self) -> None:
        # ast.unparse normalises quoting, so match the text not the quotes.
        build_automation = _method(SCREEN, "_build_automation").replace('"', "'")
        assert "fill='both', expand=True" in build_automation


class TestOneRowOfControls:
    """The page stacked its own filter row above the grid's own toolbar."""

    def test_the_screen_shares_the_grids_control_row(self) -> None:
        automation = _method(SCREEN, "_build_automation")
        assert "self._inventory_table.toolbar" in automation, (
            "the screen builds a second control row above the table again"
        )

    def test_the_grid_does_not_draw_a_second_search_box(self) -> None:
        """The screen owns the search, so the toolbar must not add one too."""
        automation = _method(SCREEN, "_build_automation").replace('"', "'")
        assert "show_quick_filter=False" in automation

    def test_a_table_still_gets_its_own_search_by_default(self) -> None:
        """Turning it off here must not turn it off everywhere."""
        source = TABLES.read_text(encoding="utf-8")
        assert "show_quick_filter: bool = True" in source


class TestScrollbarsEarnTheirSpace:
    """A scrollbar with nothing to scroll is clutter, and costs height."""

    def test_a_scrollbar_hides_when_its_range_is_fully_visible(self) -> None:
        source = _method(TABLES, "_autohide")
        assert "grid_remove()" in source
        assert "float(first) <= 0.0 and float(last) >= 1.0" in source

    def test_both_scrollbars_go_through_it(self) -> None:
        source = TABLES.read_text(encoding="utf-8")
        assert "yscrollcommand=lambda first, last: self._autohide(vertical" in source
        assert "xscrollcommand=lambda first, last: self._autohide(horizontal" in source

    def test_it_hides_and_shows_against_a_real_scrollbar(self, tk_root) -> None:
        """The decision itself, driven with the values Tk reports.

        This calls the handler rather than resizing a window, because a
        withdrawn root never computes a viewport and so never issues a
        scrollcommand at all - the window would have to be on screen for the
        end-to-end path to run.
        """
        from aethra_sec.ui.widgets.tables import Column, DataTable

        table = DataTable(tk_root, (Column("ip", "IP"),), height=5)
        try:
            bar = table._vbar
            # Whole range visible -> nothing to scroll -> gone.
            table._autohide(bar, "0.0", "1.0")
            assert bar.grid_info() == {}
            # A tenth of the rows visible -> the bar is needed.
            table._autohide(bar, "0.0", "0.1")
            assert bar.grid_info() != {}
            # Scrolled to the bottom of a long list: still needed.
            table._autohide(bar, "0.9", "1.0")
            assert bar.grid_info() != {}
            table._autohide(bar, "0.0", "1.0")
            assert bar.grid_info() == {}
        finally:
            table.destroy()

    def test_repeating_the_same_state_touches_no_geometry(self, tk_root) -> None:
        """The scrollcommand fires constantly; it must be cheap when idle."""
        from aethra_sec.ui.widgets.tables import Column, DataTable

        table = DataTable(tk_root, (Column("ip", "IP"),), height=5)
        try:
            bar = table._vbar
            calls: list[str] = []
            bar.grid_remove = lambda: calls.append("remove")  # type: ignore[method-assign]
            bar.grid = lambda *a, **k: calls.append("grid")  # type: ignore[method-assign]
            table._autohide(bar, "0.0", "0.1")
            assert calls == ["grid"]
            for _ in range(20):
                table._autohide(bar, "0.0", "0.1")
            assert calls == ["grid"], "an unchanged state re-gridded the scrollbar"
        finally:
            table.destroy()


class TestTheInventoryQueryUsesItsIndexes:
    """The refresh query scanned snort_alerts once per row on the page."""

    def test_the_alert_count_does_not_or_across_two_columns(self) -> None:
        source = (ROOT / "aethra_sec" / "database" / "repositories" / "hosts.py").read_text(
            encoding="utf-8"
        )
        assert "src_host_id = h.id OR a.dst_host_id = h.id" not in source, (
            "the OR is back: it cannot use either foreign-key index, and "
            "correlated per row it becomes a full scan of snort_alerts for "
            "every host on the page"
        )
        assert "_ALERT_COUNT_SQL" in source

    def test_each_side_seeks_on_its_own_column(self) -> None:
        from aethra_sec.database.repositories.hosts import _ALERT_COUNT_SQL

        assert "a.src_host_id = h.id" in _ALERT_COUNT_SQL
        assert "a.dst_host_id = h.id" in _ALERT_COUNT_SQL

    def test_an_alert_at_both_ends_is_counted_once(self) -> None:
        """Splitting the OR into a sum double-counts without this guard."""
        from aethra_sec.database.repositories.hosts import _ALERT_COUNT_SQL

        assert "a.src_host_id <> h.id" in _ALERT_COUNT_SQL, (
            "the second side must exclude rows the first already counted"
        )

    def test_both_callers_share_the_one_expression(self) -> None:
        source = (ROOT / "aethra_sec" / "database" / "repositories" / "hosts.py").read_text(
            encoding="utf-8"
        )
        assert source.count("{_ALERT_COUNT_SQL} AS alert_count") == 2


class TestTheVerboseDiagnosticsAreCollapsed:
    """Kept in full - just not occupying the table's height by default."""

    def test_the_notes_live_behind_a_disclosure(self) -> None:
        controls = _method(SCREEN, "_build_controls")
        for note in ("_profile_note", "_authorization_note", "_interface_note"):
            assert f"{note} = ttk.Label(self._details_box" in controls, (
                f"{note} is packed straight onto the page again"
            )

    def test_the_disclosure_starts_closed(self) -> None:
        controls = _method(SCREEN, "_build_controls")
        assert "self._details_open = False" in controls
        # The box itself is not packed at build time.
        assert "self._details_box.pack(" not in controls

    def test_the_interface_clash_keeps_a_compact_visible_line(self) -> None:
        """The condition stays visible; only its paragraph is folded away."""
        load = _method(SCREEN, "_load_interfaces")
        assert "_interface_warning.configure" in load
        assert "_interface_note.configure(text=warning" in load, (
            "the real diagnostic text must still be stored, not discarded"
        )

    def test_the_toggle_opens_and_closes(self) -> None:
        toggle = _method(SCREEN, "_toggle_details")
        assert "pack_forget()" in toggle and "self._details_box.pack(" in toggle


class TestTheRefreshReconcilesInsteadOfRebuilding:
    def test_the_inventory_reconciles_on_a_stable_key(self) -> None:
        render = _method(SCREEN, "_render_inventory").replace('"', "'")
        assert "reconcile_rows(" in render, "the table is rebuilt on every refresh"
        assert "key='ip'" in render

    def test_reconcile_falls_back_when_position_depends_on_content(self) -> None:
        """An active sort or filter has no stable position to patch."""
        source = _method(TABLES, "reconcile_rows")
        for guard in ("_sort_key", "_filter_text", "_quick_text", "_max_rows"):
            assert guard in source, f"reconcile does not fall back on {guard}"
        assert "self.set_rows(incoming)" in source

    def test_an_unchanged_row_costs_no_tk_call(self) -> None:
        source = _method(TABLES, "reconcile_rows")
        assert "self._painted.get(row_id) != painted" in source

    def test_the_detail_cell_is_truncated(self) -> None:
        """A paragraph in every row made the table unreadable."""
        detail = _method(SCREEN, "_detail_text")
        assert "truncate(" in detail


class TestReconcileBehaviour:
    """The diff itself, exercised without a display."""

    def _table(self, root):
        from aethra_sec.ui.widgets.tables import Column, DataTable

        return DataTable(
            root, (Column("ip", "IP"), Column("state", "State")), height=5
        )

    def test_it_updates_inserts_and_removes_by_key(self, tk_root) -> None:
        table = self._table(tk_root)
        try:
            table.set_rows(
                [{"ip": "10.0.0.1", "state": "UP"}, {"ip": "10.0.0.2", "state": "UP"}]
            )
            assert table.reconcile_rows(
                [
                    {"ip": "10.0.0.1", "state": "SCANNING"},
                    {"ip": "10.0.0.3", "state": "UP"},
                ],
                key="ip",
            )
            addresses = [table._rows[i]["ip"] for i in table.tree.get_children()]
            assert addresses == ["10.0.0.1", "10.0.0.3"], "keys were not reconciled"
            first = table.tree.get_children()[0]
            assert table.tree.item(first, "values")[1] == "SCANNING"
        finally:
            table.destroy()

    def test_it_never_invents_a_row(self, tk_root) -> None:
        """An empty result empties the table - it does not keep stale hosts."""
        table = self._table(tk_root)
        try:
            table.set_rows([{"ip": "10.0.0.1", "state": "UP"}])
            table.reconcile_rows([], key="ip")
            assert table.tree.get_children() == ()
            assert table.row_count == 0
        finally:
            table.destroy()
