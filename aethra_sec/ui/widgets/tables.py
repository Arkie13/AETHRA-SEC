"""Record tables built on ``ttk.Treeview`` (§12, §41, §42).

:class:`DataTable` provides the behaviour every AETHRA-SEC grid needs: column
sizing, severity colouring, click-to-sort, live filtering, a bounded row cap for
the live packet view, selection callbacks and CSV export.

The row cap matters: a live capture would otherwise grow the widget without
bound. Rows are trimmed from the oldest end and the trim is visible in the row
counter, so the operator can see the view is windowed while the database keeps
the full history (§105).
"""

from __future__ import annotations

import tkinter as tk
from dataclasses import dataclass
from tkinter import ttk
from typing import Any, Callable, Iterable, Sequence

from aethra_sec.ui.theme import (
    ICONS,
    PALETTE,
    security_colour,
    severity_colour,
    severity_glyph,
    state_colour,
    status_colour,
)
from aethra_sec.ui.widgets.cards import ControlBar
from aethra_sec.ui.widgets.tooltip import attach_tooltip


@dataclass(frozen=True)
class Column:
    """One table column."""

    key: str
    title: str
    width: int = 120
    anchor: str = "w"
    stretch: bool = False
    colour_by: str = ""  # "severity" | "state" | "status" | ""
    #: Prefix the cell with a severity shape, so severity is not colour-only.
    glyph: bool = False
    #: Draw a truthy value as this compact mark instead of its own text.
    #:
    #: The *stored* value stays the word, which is what a copy, an export and
    #: the quick filter see - so a CSV reads "UNREVIEWED" where the table
    #: shows a dot, and typing the word still finds the rows. Only the on
    #: screen cell is abbreviated.
    marker: str = ""


@dataclass(frozen=True)
class RowAction:
    """One entry in a table's right-click menu."""

    label: str
    run: Callable[[dict[str, Any]], None]
    #: Called with the row to decide whether the entry is enabled.
    enabled_for: Callable[[dict[str, Any]], bool] | None = None


class DataTable(ttk.Frame):
    """A themed, sortable, filterable record grid."""

    def __init__(
        self,
        parent: tk.Misc,
        columns: Sequence[Column],
        *,
        height: int = 14,
        max_rows: int | None = None,
        on_select: Callable[[dict[str, Any]], None] | None = None,
        on_activate: Callable[[dict[str, Any]], None] | None = None,
        mono: bool = False,
        selectmode: str = "browse",
        actions: Sequence[RowAction] = (),
        show_footer: bool = True,
        show_toolbar: bool = True,
        show_quick_filter: bool = True,
        empty_text: str = "No records to display",
    ) -> None:
        """Create the table.

        Args:
            columns: column definitions in display order.
            max_rows: cap on retained rows (used by the live packet table).
            on_select: called with the selected row's data.
            on_activate: called on double-click / Return.
            actions: right-click menu entries for the row under the pointer.
            show_footer: draw the "showing X of Y" counter beneath the grid.
            show_toolbar: draw the quick filter and column picker above it.
            show_quick_filter: draw the toolbar's own search box. A screen that
                already owns a search turns this off and adds that search to
                :attr:`toolbar` instead, so the page shows one search box on
                one row rather than two boxes on two.
            empty_text: message shown in the footer when there are no rows.
        """
        super().__init__(parent, style="Card.TFrame")
        self._columns = list(columns)
        #: Columns currently drawn. Hiding one never discards its data - the
        #: row keeps every field, and exports still carry all of them.
        self._visible_keys: list[str] = [c.key for c in self._columns]
        self._max_rows = max_rows
        self._on_select = on_select
        self._on_activate = on_activate
        self._rows: dict[str, dict[str, Any]] = {}
        self._order: list[str] = []
        self._sort_key: str | None = None
        self._sort_reverse = False
        self._filter_text = ""
        #: Text typed into the table's own filter box, ANDed with the screen's.
        self._quick_text = ""
        #: row id -> the (values, tags) last drawn for it, so an incremental
        #: reconcile can skip Tk entirely for a row that has not changed.
        self._painted: dict[str, tuple[tuple, tuple]] = {}
        self._filter_predicate: Callable[[dict[str, Any]], bool] | None = None
        self._next_id = 0
        self._trimmed = 0
        #: Rows currently in the tree. Tracked so an append never has to ask
        #: the widget, which answers by building a tuple of every row.
        self._rendered = 0
        self._actions = list(actions)
        self._empty_text = empty_text
        self._hovered: str = ""
        #: Rows the operator has marked. Held by row id rather than position,
        #: so a mark survives sorting, filtering and later arrivals - the row
        #: keeps its mark wherever it moves to.
        self._marked: set[str] = set()

        keys = [c.key for c in self._columns]
        self.tree = ttk.Treeview(
            self,
            columns=keys,
            show="headings",
            height=height,
            selectmode=selectmode,  # type: ignore[arg-type]
            style="Mono.Treeview" if mono else "Treeview",
        )
        for column in self._columns:
            self.tree.heading(
                column.key,
                text=column.title,
                anchor=column.anchor,  # type: ignore[arg-type]
                command=lambda key=column.key: self.sort_by(key),
            )
            self.tree.column(
                column.key,
                width=column.width,
                anchor=column.anchor,  # type: ignore[arg-type]
                stretch=column.stretch,
                minwidth=40,
            )

        vertical = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview)
        horizontal = ttk.Scrollbar(self, orient="horizontal", command=self.tree.xview)
        self._vbar, self._hbar = vertical, horizontal
        #: Scrollbar path -> whether it is currently gridded.
        self._bars_shown: dict[str, bool] = {}
        # A scrollbar that cannot scroll anything is clutter, and the
        # horizontal one costs the grid a row of height it could be showing
        # records in. Each hides itself when its whole range is visible.
        #
        # This cannot oscillate: the horizontal bar occupies height and
        # appears on width overflow, the vertical one occupies width and
        # appears on height overflow, so neither can cause the other's
        # condition to flip back.
        self.tree.configure(
            yscrollcommand=lambda first, last: self._autohide(vertical, first, last),
            xscrollcommand=lambda first, last: self._autohide(horizontal, first, last),
        )
        self._toolbar: ControlBar | None = None
        self._filter_var: tk.StringVar | None = None
        if show_toolbar:
            self._build_toolbar(show_quick_filter)

        self.tree.grid(row=1, column=0, sticky="nsew")
        vertical.grid(row=1, column=1, sticky="ns")
        horizontal.grid(row=2, column=0, sticky="ew")
        self.rowconfigure(1, weight=1)
        self.columnconfigure(0, weight=1)

        self._footer: ControlBar | None = None
        self._counter: ttk.Label | None = None
        self._hint: ttk.Label | None = None
        if show_footer:
            # A control bar rather than a plain frame: on a narrow window the
            # keyboard hint gives way instead of running into the row count.
            self._footer = ControlBar(self, padding=(2, 4))
            self._footer.grid(row=3, column=0, columnspan=2, sticky="ew")
            self._counter = ttk.Label(
                self._footer, text=empty_text, style="CardDim.TLabel"
            )
            self._footer.add(self._counter, side="left")
            self._hint = ttk.Label(self._footer, text="", style="CardDim.TLabel")
            self._footer.add(self._hint, side="right", optional=True)
            self._update_hint()

        # Where two of a row's tags set the same option, a Treeview takes the
        # tag that was *configured* first - the order of the item's own tag
        # list has nothing to do with it. So these are declared in priority
        # order: the pointer beats severity, and severity beats the stripe.
        self.tree.tag_configure("hover", background=PALETTE.surface_hover)
        # A marked row outranks its severity band: marking is the operator's
        # own annotation, and it would be useless if a critical row could hide
        # it. Only the pointer highlight, configured above, beats it.
        self.tree.tag_configure(
            "marked", background=PALETTE.accent_dim, foreground=PALETTE.text
        )
        # The two severities that demand attention carry a tinted row band as
        # well as coloured text: on a long queue the band is what an analyst
        # navigates by, and a critical row is findable without reading a word.
        # Everything below high keeps the ordinary stripe, because a band on
        # most of the rows would be a band on none of them.
        for name, colour, fill in (
            ("sev_critical", PALETTE.critical, PALETTE.critical_soft),
            ("sev_high", PALETTE.high, PALETTE.high_soft),
            ("sev_medium", PALETTE.medium, ""),
            ("sev_low", PALETTE.low, ""),
            ("sev_info", PALETTE.info, ""),
            ("sev_ok", PALETTE.ok, ""),
            ("sev_offline", PALETTE.offline, ""),
            ("sev_muted", PALETTE.text_muted, ""),
        ):
            if fill:
                self.tree.tag_configure(name, foreground=colour, background=fill)
            else:
                self.tree.tag_configure(name, foreground=colour)
        self.tree.tag_configure("odd", background=PALETTE.surface)
        self.tree.tag_configure("even", background=PALETTE.surface_alt)

        self._menu = tk.Menu(self.tree, tearoff=0)
        self._menu.configure(
            background=PALETTE.surface_raised, foreground=PALETTE.text,
            activebackground=PALETTE.accent_dim, activeforeground=PALETTE.text,
            borderwidth=0, relief="flat",
        )
        # ``tk_popup`` takes a pointer grab so the posted menu receives the
        # clicks aimed at it. The grab is given back when the menu goes away -
        # never while it is still on screen, or every click would land on the
        # widget underneath and no action would run.
        self._menu.bind("<Unmap>", self._release_menu_grab, add="+")

        self.tree.bind("<<TreeviewSelect>>", self._handle_select)
        self.tree.bind("<Double-1>", self._handle_activate)
        self.tree.bind("<Return>", self._handle_activate)
        self.tree.bind("<Motion>", self._handle_motion)
        self.tree.bind("<Leave>", self._handle_pointer_leave)
        self.tree.bind("<Button-3>", self._handle_context_menu)
        self.tree.bind("<Control-c>", self._copy_selection)
        self.tree.bind("<Control-C>", self._copy_selection)
        self.tree.bind("<Control-a>", self._select_all)
        self.tree.bind("<Control-A>", self._select_all)
        # Keyboard navigation: the arrow keys are the Treeview's own, but Home,
        # End and the menu key are not, and an analyst working a long queue
        # from the keyboard needs all of them.
        self.tree.bind("<Home>", self._select_edge_first)
        self.tree.bind("<End>", self._select_edge_last)
        self.tree.bind("<Shift-F10>", self._menu_from_keyboard)
        # The dedicated menu key exists on Windows keyboards and is not a
        # keysym every X11 build knows, so binding it is best-effort.
        try:
            self.tree.bind("<App>", self._menu_from_keyboard)
        except tk.TclError:
            pass

    # ------------------------------------------------------------------
    # Toolbar: quick filter and column visibility
    # ------------------------------------------------------------------
    def _autohide(self, bar: ttk.Scrollbar, first: str, last: str) -> None:
        """Show a scrollbar only while it has somewhere to scroll.

        The shown/hidden state is tracked here rather than read back from the
        widget: ``winfo_ismapped`` reports 0 for every child of a window that
        is merely withdrawn, which would make this flap on a hidden page.
        """
        bar.set(first, last)
        needed = not (float(first) <= 0.0 and float(last) >= 1.0)
        if self._bars_shown.get(str(bar)) == needed:
            return
        self._bars_shown[str(bar)] = needed
        if needed:
            bar.grid()
        else:
            bar.grid_remove()  # keeps the cell, so nothing else shifts

    def _build_toolbar(self, quick_filter: bool = True) -> None:
        """A filter box and a column picker above the grid.

        Both narrow what is *shown*; neither touches what is held. The counter
        underneath always states the difference, so a filtered view can never
        be mistaken for the whole record set.
        """
        self._toolbar = ControlBar(self, padding=(0, 0, 0, 6))
        self._toolbar.grid(row=0, column=0, columnspan=2, sticky="ew")

        if quick_filter:
            glyph = ttk.Label(self._toolbar, text="⌕", style="CardDim.TLabel")
            self._toolbar.add(glyph, side="left", padx=(2, 4))
            self._filter_var = tk.StringVar()
            entry = ttk.Entry(self._toolbar, textvariable=self._filter_var, width=24)
            self._toolbar.add(entry, side="left")
            self._filter_var.trace_add("write", lambda *_: self._apply_quick_filter())
            entry.bind("<Escape>", self._clear_filter)
            entry.bind("<Down>", lambda _event: (self.tree.focus_set(), "break")[1])
            attach_tooltip(
                entry, "Filter these rows as you type. Esc clears it."
            )

        self._columns_button = ttk.Button(
            self._toolbar, text="Columns", style="Tool.TButton",
            command=self._open_column_menu,
        )
        self._toolbar.add(self._columns_button, side="right", padx=(6, 2))
        attach_tooltip(
            self._columns_button,
            "Choose which columns are shown. Hidden columns keep their data "
            "and are still exported.",
        )

        self._column_menu = tk.Menu(self, tearoff=0)
        self._column_menu.configure(
            background=PALETTE.surface_raised, foreground=PALETTE.text,
            activebackground=PALETTE.accent_dim, activeforeground=PALETTE.text,
            borderwidth=0, relief="flat",
        )
        self._column_menu.bind("<Unmap>", self._release_column_grab, add="+")
        self._column_vars: dict[str, tk.BooleanVar] = {}

    def _apply_quick_filter(self) -> None:
        """Re-render for the text typed into the table's own filter box.

        Kept separate from :meth:`set_filter`, which a screen uses for its own
        structured filters; the two narrow the view together rather than one
        silently clearing the other.
        """
        if self._filter_var is None:
            return
        self._quick_text = self._filter_var.get().strip().lower()
        self._render()

    def _clear_filter(self, _event: tk.Event | None = None) -> str:
        """Empty the quick filter."""
        if self._filter_var is not None:
            self._filter_var.set("")
        return "break"

    def _release_column_grab(self, _event: tk.Event | None = None) -> None:
        """Give the pointer grab back once the column menu is dismissed."""
        try:
            self._column_menu.grab_release()
        except tk.TclError:  # pragma: no cover - menu already destroyed
            pass

    def _open_column_menu(self) -> None:
        """Show the column picker under its button."""
        self._column_menu.delete(0, "end")
        for column in self._columns:
            variable = self._column_vars.setdefault(
                column.key, tk.BooleanVar(value=column.key in self._visible_keys)
            )
            variable.set(column.key in self._visible_keys)
            self._column_menu.add_checkbutton(
                label=column.title,
                variable=variable,
                command=lambda key=column.key: self._toggle_column(key),
            )
        self._column_menu.add_separator()
        self._column_menu.add_command(
            label="Show all columns", command=self._show_all_columns
        )
        button = self._columns_button
        try:
            self._column_menu.tk_popup(
                button.winfo_rootx(), button.winfo_rooty() + button.winfo_height()
            )
        except tk.TclError:  # pragma: no cover - no display for the popup
            self._release_column_grab()

    def _toggle_column(self, key: str) -> None:
        """Show or hide one column, keeping at least one on screen."""
        wanted = [
            column.key for column in self._columns
            if self._column_vars[column.key].get()
        ]
        if not wanted:
            # Hiding the last column would leave an unreadable grid.
            self._column_vars[key].set(True)
            return
        self._visible_keys = wanted
        self._apply_visible_columns()

    def _show_all_columns(self) -> None:
        """Restore every column."""
        self._visible_keys = [column.key for column in self._columns]
        for variable in self._column_vars.values():
            variable.set(True)
        self._apply_visible_columns()

    def _apply_visible_columns(self) -> None:
        """Tell the tree which of its columns to display."""
        try:
            self.tree.configure(displaycolumns=tuple(self._visible_keys))
        except tk.TclError:  # pragma: no cover - widget torn down
            return
        self._update_counter(self.visible_count)

    # ------------------------------------------------------------------
    # Data
    # ------------------------------------------------------------------
    def set_rows(self, rows: Iterable[dict[str, Any]]) -> None:
        """Replace every row."""
        self.clear()
        self.add_rows(rows)

    def reconcile_rows(self, rows: Iterable[dict[str, Any]], *, key: str) -> bool:
        """Update the table in place from ``rows``, matched on ``key``.

        A periodically refreshed table must not be rebuilt from scratch. Every
        ``set_rows`` deletes and re-inserts every item, which throws away the
        scroll position and the selection: an operator scrolled halfway down
        the host inventory was thrown back to the top each time the refresh
        fired, which is what made the table feel impossible to scroll.

        This patches only what changed - values on rows that differ, inserts
        for new keys, deletes for keys that have gone - and leaves the view
        where the operator put it.

        Returns:
            True when the in-place diff was applied. False when it fell back
            to a full rebuild, which happens with an active sort or filter:
            those make a row's position depend on its content, so there is no
            stable position to patch.
        """
        incoming = [dict(row) for row in rows]
        if (
            self._sort_key
            or self._filter_text
            or self._quick_text
            or self._filter_predicate is not None
            or self._max_rows is not None
        ):
            self.set_rows(incoming)
            return False

        try:
            first, _last = self.tree.yview()
            selected_keys = {
                str(self._rows[iid].get(key))
                for iid in self.tree.selection()
                if iid in self._rows
            }
        except tk.TclError:  # pragma: no cover - widget torn down
            return False

        existing: dict[str, str] = {}
        for row_id in self._order:
            row = self._rows.get(row_id)
            if row is not None:
                existing[str(row.get(key))] = row_id

        order: list[str] = []
        seen: set[str] = set()
        for index, row in enumerate(incoming):
            row_key = str(row.get(key))
            seen.add(row_key)
            row_id = existing.get(row_key)
            stripe = "even" if index % 2 else "odd"
            colour_tag = self._colour_tag(row)
            tags = [colour_tag] if colour_tag else []
            tags.append(stripe)
            values = [self._cell(row, column) for column in self._columns]
            painted = (tuple(values), tuple(tags))
            if row_id is None:
                self._next_id += 1
                row_id = f"r{self._next_id}"
                self._rows[row_id] = row
                try:
                    self.tree.insert(
                        "", index, iid=row_id, values=values, tags=tuple(tags)
                    )
                except tk.TclError:  # pragma: no cover
                    continue
                self._painted[row_id] = painted
            else:
                self._rows[row_id] = row
                # A refresh where nothing about this row changed costs no Tk
                # call at all - the comparison is against what was last drawn,
                # so a steady table is effectively free to "refresh".
                if self._painted.get(row_id) != painted:
                    try:
                        self.tree.item(row_id, values=values, tags=tuple(tags))
                    except tk.TclError:  # pragma: no cover
                        continue
                    self._painted[row_id] = painted
                try:
                    if self.tree.index(row_id) != index:
                        self.tree.move(row_id, "", index)
                except tk.TclError:  # pragma: no cover
                    continue
            order.append(row_id)

        for row_key, row_id in existing.items():
            if row_key in seen:
                continue
            self._rows.pop(row_id, None)
            self._painted.pop(row_id, None)
            self._marked.discard(row_id)
            try:
                if self.tree.exists(row_id):
                    self.tree.delete(row_id)
            except tk.TclError:  # pragma: no cover
                pass

        self._order = order
        self._rendered = len(order)
        restore = [
            row_id for row_id in order
            if str(self._rows[row_id].get(key)) in selected_keys
        ]
        try:
            if restore:
                self.tree.selection_set(restore)
            self.tree.yview_moveto(first)
        except tk.TclError:  # pragma: no cover
            pass
        self._update_counter(self.visible_count)
        return True

    def add_rows(self, rows: Iterable[dict[str, Any]]) -> None:
        """Append rows, honouring the row cap.

        Appending costs the rows being appended, not the rows already held.
        That distinction is the difference between a live packet table that
        keeps up with a flood and one that stops the interface: a full redraw
        of a 2,000-row grid costs ~37 ms of Tk thread time, so a table redrawn
        on every batch cannot service more than about 25 batches a second
        before the event loop falls behind and never recovers.
        """
        added = [self._append(row) for row in rows]
        self._append_incrementally(added)

    def add_row(self, row: dict[str, Any]) -> str:
        """Append one row and return its internal id."""
        row_id = self._append(row)
        self._append_incrementally([row_id])
        return row_id

    def _append_incrementally(self, added: Sequence[str]) -> None:
        """Insert the new rows and remove whatever the cap pushed out.

        A sort makes position depend on content rather than arrival, so there
        is no correct "end" to append to and the table falls back to a full
        redraw. Live tables do not sort by default, which is why the fast path
        is the one that runs during a capture.
        """
        if self._sort_key:
            self._trim()
            self._render()
            return

        dropped = self._trim()
        for row_id in dropped:
            # A row can be evicted in the same call that added it, and a row
            # filtered out was never inserted at all, so the count may only be
            # reduced for rows the tree actually holds.
            try:
                if not self.tree.exists(row_id):
                    continue
                self.tree.delete(row_id)
            except tk.TclError:  # pragma: no cover - widget torn down
                continue
            self._rendered -= 1

        surviving = [row_id for row_id in added if row_id in self._rows]
        if not surviving and not dropped:
            return
        # The stripe alternates by position, so appending has to continue the
        # sequence the table already has rather than restart it. The count is
        # tracked rather than read back from the tree: get_children() builds a
        # tuple of every row, which would put the O(n) straight back in.
        index = self._rendered
        for row_id in surviving:
            row = self._rows[row_id]
            if not self._matches(row):
                continue
            values = [self._cell(row, column) for column in self._columns]
            colour_tag = self._colour_tag(row)
            tags = [colour_tag] if colour_tag else []
            tags.append("even" if index % 2 else "odd")
            if row_id in self._marked:
                tags.insert(0, "marked")
            try:
                self.tree.insert("", "end", iid=row_id, values=values, tags=tuple(tags))
            except tk.TclError:  # pragma: no cover - duplicate id, widget gone
                continue
            index += 1
        self._rendered = index
        self._update_counter(self.visible_count)

    def _append(self, row: dict[str, Any]) -> str:
        """Store a row without re-rendering."""
        self._next_id += 1
        row_id = f"r{self._next_id}"
        self._rows[row_id] = dict(row)
        self._order.append(row_id)
        return row_id

    def _trim(self) -> list[str]:
        """Drop the oldest rows once the cap is exceeded.

        Returns the ids removed, so an incremental append can take the same
        rows out of the tree without walking all of it.
        """
        if self._max_rows is None:
            return []
        excess = len(self._order) - self._max_rows
        if excess <= 0:
            return []
        dropped = self._order[:excess]
        for row_id in dropped:
            self._rows.pop(row_id, None)
            # A mark belongs to a row; once the row has left the view buffer
            # the mark has nothing to refer to and must not accumulate.
            self._marked.discard(row_id)
        self._order = self._order[excess:]
        self._trimmed += excess
        return dropped

    def clear(self) -> None:
        """Remove every row."""
        self._rows.clear()
        self._order.clear()
        self._painted.clear()
        self._marked.clear()
        self._trimmed = 0
        self._rendered = 0
        for item in self.tree.get_children():
            self.tree.delete(item)

    @property
    def toolbar(self) -> ControlBar | None:
        """The grid's own control row, for a screen to share.

        A screen whose controls belong to this table adds them here rather
        than packing a second row above it: the bar already reflows, and one
        row of controls leaves the grid the height that two rows spend on
        chrome. ``None`` when the table was built without a toolbar.
        """
        return self._toolbar

    @property
    def row_count(self) -> int:
        """Rows currently held (before filtering)."""
        return len(self._order)

    @property
    def visible_count(self) -> int:
        """Rows currently displayed (after filtering)."""
        return self._rendered

    @property
    def trimmed_count(self) -> int:
        """Rows dropped because of the display cap."""
        return self._trimmed

    def rows(self, *, visible_only: bool = False) -> list[dict[str, Any]]:
        """Return row data, optionally only the filtered rows."""
        if visible_only:
            return [
                self._rows[item] for item in self.tree.get_children() if item in self._rows
            ]
        return [self._rows[row_id] for row_id in self._order if row_id in self._rows]

    # ------------------------------------------------------------------
    # Filtering and sorting
    # ------------------------------------------------------------------
    def set_filter(
        self,
        text: str = "",
        predicate: Callable[[dict[str, Any]], bool] | None = None,
    ) -> None:
        """Apply a free-text filter and/or a structured predicate (§13, §42)."""
        self._filter_text = (text or "").strip().lower()
        self._filter_predicate = predicate
        self._render()

    def sort_by(self, key: str, *, reverse: bool | None = None) -> None:
        """Sort by a column, toggling direction on repeat clicks."""
        if reverse is not None:
            self._sort_key = key
            self._sort_reverse = reverse
        elif self._sort_key == key:
            self._sort_reverse = not self._sort_reverse
        else:
            self._sort_key = key
            self._sort_reverse = False
        self._update_headings()
        self._render()

    @property
    def sort_state(self) -> tuple[str, bool]:
        """``(column key, descending)`` - used to restore a saved preference."""
        return self._sort_key or "", self._sort_reverse

    def _update_headings(self) -> None:
        """Show which column is sorted, and in which direction."""
        for column in self._columns:
            marker = ""
            if column.key == self._sort_key:
                marker = (
                    f"  {ICONS['sort_desc']}" if self._sort_reverse
                    else f"  {ICONS['sort_asc']}"
                )
            try:
                self.tree.heading(column.key, text=f"{column.title}{marker}")
            except tk.TclError:  # pragma: no cover - widget torn down
                return

    def _matches(self, row: dict[str, Any]) -> bool:
        """True when a row passes every active filter.

        A row must satisfy the screen's structured predicate, the screen's text
        filter and the table's own quick filter - they narrow together.
        """
        if self._filter_predicate is not None and not self._filter_predicate(row):
            return False
        if not self._filter_text and not self._quick_text:
            return True
        haystack = " ".join(
            str(row.get(column.key, "")) for column in self._columns
        ).lower()
        if self._filter_text and self._filter_text not in haystack:
            return False
        return not self._quick_text or self._quick_text in haystack

    def _sort_value(self, row: dict[str, Any]) -> Any:
        """Sort key for a row, ordering numbers numerically."""
        value = row.get(self._sort_key or "", "")
        raw = row.get(f"_{self._sort_key}_sort", None)
        if raw is not None:
            return raw
        if isinstance(value, (int, float)):
            return value
        text = str(value)
        try:
            return float(text.replace(",", ""))
        except ValueError:
            return text.lower()

    def _render(self) -> None:
        """Redraw the visible rows."""
        selected = set(self.tree.selection())
        for item in self.tree.get_children():
            self.tree.delete(item)

        visible = [
            row_id for row_id in self._order
            if row_id in self._rows and self._matches(self._rows[row_id])
        ]
        if self._sort_key:
            visible.sort(
                key=lambda rid: self._sort_value(self._rows[rid]),
                reverse=self._sort_reverse,
            )

        for index, row_id in enumerate(visible):
            row = self._rows[row_id]
            values = [self._cell(row, column) for column in self._columns]
            # Both tags are carried; which of them paints the row is settled
            # by the order they were configured in, not by this order.
            colour_tag = self._colour_tag(row)
            tags = [colour_tag] if colour_tag else []
            tags.append("even" if index % 2 else "odd")
            if row_id in self._marked:
                tags.insert(0, "marked")
            self.tree.insert("", "end", iid=row_id, values=values, tags=tuple(tags))

        self._rendered = len(visible)

        for row_id in selected:
            if row_id in self._rows:
                try:
                    self.tree.selection_add(row_id)
                except tk.TclError:
                    pass

        self._update_counter(len(visible))

    def set_empty_text(self, text: str) -> None:
        """Change the message shown when the table holds no rows.

        Live screens use this to say why the table is empty - waiting for the
        first packet reads very differently from a capture that has stopped.
        """
        self._empty_text = text
        if not self._order:
            self._update_counter(0)

    def _update_counter(self, visible: int) -> None:
        """Report how many records are shown out of how many are held."""
        if self._counter is None:
            return
        total = len(self._order)
        if total == 0:
            text = self._empty_text
        elif visible == total:
            text = f"{total:,} record(s)"
        else:
            text = f"Showing {visible:,} of {total:,} record(s)"
        if self._trimmed:
            text += (
                f"  ·  {self._trimmed:,} older row(s) dropped from this view "
                "(the database keeps them)"
            )
        try:
            self._counter.configure(text=text)
        except tk.TclError:  # pragma: no cover - widget torn down
            pass

    def _update_hint(self) -> None:
        """Show the keyboard/mouse affordances this table supports."""
        if self._hint is None:
            return
        parts = ["click a heading to sort"]
        if self._on_activate is not None:
            parts.append("double-click to open")
        if self._actions:
            parts.append("right-click for actions")
        if self._toolbar is not None:
            parts.append("Home/End jump")
        parts.append("Ctrl+C copies")
        self._hint.configure(text="  ·  ".join(parts))

    @staticmethod
    def _cell(row: dict[str, Any], column: Column, *, display: bool = True) -> str:
        """Render one cell.

        Args:
            display: False renders the value as it should be *read* rather
                than as it is drawn, which is what a copy or an export wants:
                a marker column then yields its stored word instead of the
                glyph that stands in for it on screen.
        """
        value = row.get(column.key, "")
        text = "" if value is None else str(value)
        if column.marker and display:
            return column.marker if text else ""
        if column.glyph and text:
            glyph = severity_glyph(text)
            if glyph:
                return f"{glyph} {text}"
        return text

    def _colour_tag(self, row: dict[str, Any]) -> str:
        """Pick the row's foreground tag from its severity/state column."""
        for column in self._columns:
            if not column.colour_by:
                continue
            value = str(row.get(column.key, "")).upper()
            colour = {
                "severity": severity_colour,
                "state": state_colour,
                "status": status_colour,
                "security": security_colour,
            }[column.colour_by](value)
            if colour == PALETTE.text:
                # security_colour's "no claim" answer. Left untagged so the
                # cell keeps the table's ordinary foreground rather than being
                # given a severity colour it has not earned.
                return ""
            return {
                PALETTE.critical: "sev_critical",
                PALETTE.high: "sev_high",
                PALETTE.medium: "sev_medium",
                PALETTE.low: "sev_low",
                PALETTE.info: "sev_info",
                PALETTE.ok: "sev_ok",
                PALETTE.offline: "sev_offline",
            }.get(colour, "sev_muted")
        return ""

    # ------------------------------------------------------------------
    # Selection
    # ------------------------------------------------------------------
    def selected_row(self) -> dict[str, Any] | None:
        """The currently selected row's data, if any."""
        selection = self.tree.selection()
        if not selection:
            return None
        return self._rows.get(selection[0])

    def selected_rows(self) -> list[dict[str, Any]]:
        """Every selected row's data."""
        return [self._rows[i] for i in self.tree.selection() if i in self._rows]

    # ------------------------------------------------------------------
    # Marking
    # ------------------------------------------------------------------
    def selected_row_id(self) -> str | None:
        """The internal id of the selected row, for marking it."""
        selection = self.tree.selection()
        return selection[0] if selection else None

    def is_marked(self, row_id: str) -> bool:
        """True when a row carries the operator's mark."""
        return row_id in self._marked

    def set_marked(self, row_id: str, marked: bool) -> None:
        """Mark or unmark one row and repaint it in place.

        Only the display changes: marking is an operator annotation about a
        real captured packet, and it neither alters nor re-interprets the
        packet itself.
        """
        if not row_id or row_id not in self._rows:
            return
        if marked:
            self._marked.add(row_id)
        else:
            self._marked.discard(row_id)
        try:
            if not self.tree.exists(row_id):
                return
            tags = [tag for tag in self.tree.item(row_id, "tags") if tag != "marked"]
            if marked:
                tags.insert(0, "marked")
            self.tree.item(row_id, tags=tuple(tags))
        except tk.TclError:  # pragma: no cover - row went away mid-refresh
            pass

    def toggle_mark(self, row_id: str) -> bool:
        """Flip a row's mark; returns its new state."""
        marked = not self.is_marked(row_id)
        self.set_marked(row_id, marked)
        return marked

    @property
    def marked_count(self) -> int:
        """How many rows are marked, including any filtered out of view."""
        return len(self._marked)

    def marked_rows(self) -> list[dict[str, Any]]:
        """The data of every marked row still held by the table."""
        return [self._rows[row_id] for row_id in self._order if row_id in self._marked]

    def clear_marks(self) -> None:
        """Remove every mark, repainting the rows that carried one."""
        for row_id in list(self._marked):
            self.set_marked(row_id, False)

    def select_first(self) -> None:
        """Select the first visible row (used after a refresh)."""
        children = self.tree.get_children()
        if children:
            self.tree.selection_set(children[0])
            self.tree.focus(children[0])

    def select_where(self, match: Callable[[dict[str, Any]], bool]) -> bool:
        """Select and scroll to the first visible row the predicate accepts.

        Returns ``False`` when nothing visible matches, so a screen opened to
        show one particular record can fall back to its normal behaviour
        rather than leaving the table with nothing selected and a detail pane
        showing the wrong thing.
        """
        for row_id in self.tree.get_children():
            row = self._rows.get(row_id)
            if row is not None and match(row):
                self.tree.selection_set(row_id)
                self.tree.focus(row_id)
                try:
                    self.tree.see(row_id)
                except tk.TclError:  # pragma: no cover - torn down mid-refresh
                    pass
                return True
        return False

    def focus_table(self) -> None:
        """Put the keyboard on this table and select its first row.

        Used when an action's whole point is the contents of this table, so
        the operator can read, arrow through and copy it without the mouse.
        """
        self.tree.focus_set()
        if not self.tree.selection():
            self.select_first()

    def _handle_select(self, _event: tk.Event) -> None:
        """Forward a selection change."""
        if self._on_select is None:
            return
        row = self.selected_row()
        if row is not None:
            self._on_select(row)

    def _handle_activate(self, _event: tk.Event) -> str | None:
        """Forward a double-click / Return."""
        if self._on_activate is None:
            return None
        row = self.selected_row()
        if row is not None:
            self._on_activate(row)
        return "break"

    # ------------------------------------------------------------------
    # Pointer and keyboard interaction
    # ------------------------------------------------------------------
    def _handle_motion(self, event: tk.Event) -> None:
        """Highlight the row under the pointer."""
        row_id = self.tree.identify_row(event.y)
        if row_id == self._hovered:
            return
        self._set_hover(self._hovered, False)
        self._hovered = row_id
        self._set_hover(row_id, True)

    def _handle_pointer_leave(self, _event: tk.Event) -> None:
        """Clear the hover highlight."""
        self._set_hover(self._hovered, False)
        self._hovered = ""

    def _set_hover(self, row_id: str, hovered: bool) -> None:
        """Add or remove the hover tag without disturbing the other tags."""
        if not row_id:
            return
        try:
            tags = list(self.tree.item(row_id, "tags"))
        except tk.TclError:  # pragma: no cover - row disappeared mid-refresh
            return
        if hovered and "hover" not in tags:
            tags.insert(0, "hover")
        elif not hovered and "hover" in tags:
            tags.remove("hover")
        else:
            return
        try:
            self.tree.item(row_id, tags=tuple(tags))
        except tk.TclError:
            pass

    def set_actions(self, actions: Sequence[RowAction]) -> None:
        """Replace the right-click menu entries."""
        self._actions = list(actions)
        self._update_hint()

    def _release_menu_grab(self, _event: tk.Event | None = None) -> None:
        """Give the pointer grab back once the menu has been dismissed."""
        try:
            self._menu.grab_release()
        except tk.TclError:  # pragma: no cover - menu already destroyed
            pass

    def _handle_context_menu(self, event: tk.Event) -> str | None:
        """Open the row menu for the row under the pointer.

        The row under the pointer is selected first, and the row's own data is
        bound into each command, so an action always runs against the row that
        was right-clicked rather than whatever happened to be selected before.
        """
        if not self._actions:
            return None
        row_id = self.tree.identify_row(event.y)
        if not row_id:
            return None
        self.tree.selection_set(row_id)
        self.tree.focus(row_id)
        self.tree.see(row_id)
        row = self._rows.get(row_id)
        if row is None:
            return None

        self._menu.delete(0, "end")
        for action in self._actions:
            enabled = True
            if action.enabled_for is not None:
                try:
                    enabled = bool(action.enabled_for(row))
                except Exception:  # noqa: BLE001 - a predicate must not break the menu
                    enabled = False
            self._menu.add_command(
                label=action.label,
                command=lambda run=action.run, data=row: run(data),
                state="normal" if enabled else "disabled",
            )
        self._menu.add_separator()
        self._menu.add_command(label="Copy row", command=self._copy_selection)
        try:
            self._menu.tk_popup(event.x_root, event.y_root)
        except tk.TclError:  # pragma: no cover - no display for the popup
            self._release_menu_grab()
        return "break"

    def _copy_selection(self, _event: tk.Event | None = None) -> str:
        """Copy the selected rows to the clipboard as tab-separated text."""
        rows = self.selected_rows()
        if not rows:
            return "break"
        header = "\t".join(column.title for column in self._columns)
        body = "\n".join(
            # display=False: a pasted row should read "UNREVIEWED", not the
            # dot that stands in for it in a 58-pixel column.
            "\t".join(
                self._cell(row, column, display=False)
                for column in self._columns
            )
            for row in rows
        )
        try:
            self.clipboard_clear()
            self.clipboard_append(f"{header}\n{body}")
        except tk.TclError:  # pragma: no cover - no clipboard on this display
            pass
        return "break"

    def _select_all(self, _event: tk.Event | None = None) -> str:
        """Select every visible row."""
        children = self.tree.get_children()
        if children:
            self.tree.selection_set(children)
        return "break"

    def _select_edge(self, last: bool) -> str:
        """Jump the selection to the first or last visible row."""
        children = self.tree.get_children()
        if not children:
            return "break"
        row_id = children[-1] if last else children[0]
        self.tree.selection_set(row_id)
        self.tree.focus(row_id)
        self.tree.see(row_id)
        return "break"

    def _select_edge_first(self, _event: tk.Event | None = None) -> str:
        """Home selects the first row."""
        return self._select_edge(last=False)

    def _select_edge_last(self, _event: tk.Event | None = None) -> str:
        """End selects the last row."""
        return self._select_edge(last=True)

    def _menu_from_keyboard(self, _event: tk.Event | None = None) -> str:
        """Open the row menu for the focused row, without a pointer."""
        row_id = self.tree.focus() or (
            self.tree.selection()[0] if self.tree.selection() else ""
        )
        if not row_id:
            return "break"
        bbox = self.tree.bbox(row_id)
        offset_y = (bbox[1] + bbox[3]) if bbox else 0
        event = tk.Event()
        event.y = (bbox[1] + bbox[3] // 2) if bbox else 0
        event.x_root = self.tree.winfo_rootx() + 60
        event.y_root = self.tree.winfo_rooty() + offset_y
        self._handle_context_menu(event)
        return "break"

    def fit_columns(self, *, sample: int = 200, padding: int = 24) -> None:
        """Widen each column to the widest value actually present.

        Only the first ``sample`` visible rows are measured, so fitting a live
        packet table stays cheap.
        """
        try:
            from tkinter import font as tkfont

            measure = tkfont.Font(font=("TkDefaultFont", 9)).measure
        except Exception:  # noqa: BLE001 - fall back to a character estimate
            def measure(text: str) -> int:
                return 7 * len(text)

        visible = self.tree.get_children()[:sample]
        for column in self._columns:
            widest = measure(column.title) + 20
            for row_id in visible:
                row = self._rows.get(row_id)
                if row is None:
                    continue
                widest = max(widest, measure(self._cell(row, column)) + padding)
            try:
                self.tree.column(column.key, width=min(widest, 460))
            except tk.TclError:  # pragma: no cover - widget torn down
                return

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------
    def export_columns(self) -> tuple[str, ...]:
        """Column titles for a CSV export."""
        return tuple(column.title for column in self._columns)

    def export_rows(self, *, visible_only: bool = True) -> list[tuple[Any, ...]]:
        """Row values for a CSV export, in display order."""
        source = (
            [self._rows[i] for i in self.tree.get_children() if i in self._rows]
            if visible_only
            else self.rows()
        )
        return [
            # display=False: an exported security record must be readable, so
            # a marker column writes its word rather than its glyph.
            tuple(
                self._cell(row, column, display=False)
                for column in self._columns
            )
            for row in source
        ]
