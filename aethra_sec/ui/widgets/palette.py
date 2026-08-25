"""The command palette: Ctrl+K to reach any screen or action (§61).

An operations console has more actions than a toolbar can hold. The palette
lists every screen the signed-in session may open and every action the visible
screen has registered, filtered as you type, driven entirely from the keyboard.

It offers nothing the session is not permitted to do: entries are supplied by
the window after the same permission check the sidebar uses, and running an
action still passes through the service layer's own check (§8).
"""

from __future__ import annotations

import tkinter as tk
from dataclasses import dataclass, field
from tkinter import ttk
from typing import Callable, Sequence

from aethra_sec.ui.theme import PALETTE, Fonts, configure_listbox

#: Most entries shown at once; the list scrolls beyond this.
VISIBLE_ROWS = 10

#: Characters before the palette starts asking the database for records. One
#: character would match most of the inventory and tell the operator nothing.
MIN_SEARCH_LENGTH = 2

#: Pause after the last keystroke before the record search runs, so typing a
#: word issues one query rather than one per letter.
SEARCH_DEBOUNCE_MS = 220


@dataclass(frozen=True)
class Command:
    """One palette entry."""

    key: str
    title: str
    category: str = ""
    detail: str = ""
    shortcut: str = ""
    run: Callable[[], None] = field(default=lambda: None)

    @property
    def haystack(self) -> str:
        """Lower-cased text the filter matches against."""
        return f"{self.title} {self.category} {self.detail}".lower()


def fuzzy_match(query: str, candidate: str) -> bool:
    """True when every character of ``query`` appears in order in ``candidate``.

    Subsequence matching is what makes "vasc" find "Vulnerability Assessment ·
    Scan", which is the whole point of a palette.
    """
    if not query:
        return True
    position = 0
    for character in query:
        position = candidate.find(character, position)
        if position < 0:
            return False
        position += 1
    return True


def rank(query: str, command: Command) -> tuple[int, int, str]:
    """Sort key: exact prefix first, then earliest match, then title."""
    haystack = command.haystack
    title = command.title.lower()
    if not query:
        return (0, 0, title)
    if title.startswith(query):
        return (0, 0, title)
    index = haystack.find(query)
    if index >= 0:
        return (1, index, title)
    return (2, 0, title)


class CommandPalette(ttk.Frame):
    """A centred, keyboard-driven overlay listing the available commands."""

    def __init__(
        self, parent: tk.Misc, commands: Sequence[Command], fonts: Fonts
    ) -> None:
        """Build the overlay; call :meth:`open` to show it."""
        super().__init__(parent, style="Overlay.TFrame", padding=(2, 2))
        self._all = list(commands)
        self._matches: list[Command] = []
        self._fonts = fonts
        #: Records found for the current query, supplied asynchronously.
        self._records: list[Command] = []
        self._records_query = ""
        self._on_search: Callable[[str], None] | None = None
        self._search_job: str | None = None

        self._query = tk.StringVar()
        self._query.trace_add("write", lambda *_: self._refilter())

        header = ttk.Frame(self, style="Overlay.TFrame", padding=(14, 12, 14, 8))
        header.pack(fill="x")
        ttk.Label(header, text="⌕", style="OverlayMuted.TLabel").pack(side="left")
        self._entry = ttk.Entry(
            header, textvariable=self._query, style="Overlay.TEntry",
            font=fonts.body, width=44,
        )
        self._entry.pack(side="left", fill="x", expand=True, padx=(8, 0))

        self._list = tk.Listbox(
            self, height=VISIBLE_ROWS, activestyle="none", exportselection=False
        )
        configure_listbox(self._list, fonts)
        self._list.configure(background=PALETTE.overlay, font=fonts.body)
        self._list.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        footer = ttk.Frame(self, style="Overlay.TFrame", padding=(14, 0, 14, 10))
        footer.pack(fill="x")
        self._count = ttk.Label(footer, text="", style="OverlayDim.TLabel")
        self._count.pack(side="left")
        ttk.Label(
            footer, text="↑↓ move · Enter run · Esc close", style="OverlayDim.TLabel"
        ).pack(side="right")

        self._entry.bind("<Down>", self._move_down)
        self._entry.bind("<Up>", self._move_up)
        self._entry.bind("<Return>", self._run_selected)
        self._entry.bind("<Escape>", lambda _event: self.close())
        self._list.bind("<Double-1>", self._run_selected)
        self._list.bind("<Return>", self._run_selected)
        self._list.bind("<Escape>", lambda _event: self.close())

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    def set_commands(self, commands: Sequence[Command]) -> None:
        """Replace the command set (the visible screen's actions change)."""
        self._all = list(commands)
        self._refilter()

    def set_search_provider(self, provider: Callable[[str], None] | None) -> None:
        """Register the callback that looks real records up for a query.

        The provider runs the search off the Tk thread and hands the result
        back through :meth:`set_records`. The palette itself never touches the
        database - it only asks, and renders what comes back.
        """
        self._on_search = provider

    def set_records(self, query: str, commands: Sequence[Command]) -> None:
        """Show the records found for ``query``.

        A result that arrives after the operator has typed on is discarded:
        showing it would answer a question they are no longer asking.
        """
        if query != self._query.get().strip().lower():
            return
        self._records_query = query
        self._records = list(commands)
        self._refilter()

    def set_query(self, text: str) -> None:
        """Seed the palette with text already typed elsewhere."""
        self._query.set(text)
        self._entry.icursor("end")
        self._entry.focus_set()

    def open(self) -> None:
        """Show the palette, centred and focused."""
        self._query.set("")
        self._records = []
        self._records_query = ""
        self._refilter()
        self.place(relx=0.5, rely=0.08, anchor="n", width=760)
        self.lift()
        self._entry.focus_set()

    def close(self) -> None:
        """Hide the palette."""
        self.place_forget()

    @property
    def is_open(self) -> bool:
        """True while the palette is mapped."""
        return bool(self.winfo_ismapped())

    def toggle(self) -> None:
        """Open when closed, close when open."""
        self.close() if self.is_open else self.open()

    # ------------------------------------------------------------------
    # Filtering
    # ------------------------------------------------------------------
    def _refilter(self) -> None:
        """Recompute the visible entries for the current query."""
        query = self._query.get().strip().lower()
        matches = [c for c in self._all if fuzzy_match(query, c.haystack)]
        matches.sort(key=lambda command: rank(query, command))

        # Records are already the answer to this exact query, so they are
        # appended rather than filtered again - and they follow the screens,
        # because "open Hosts" should not be buried under thirty addresses.
        records = self._records if query and query == self._records_query else []
        self._matches = matches + list(records)

        self._list.delete(0, "end")
        for command in self._matches:
            prefix = f"{command.category} · " if command.category else ""
            suffix = f"   {command.shortcut}" if command.shortcut else ""
            detail = f"   {command.detail}" if command.detail else ""
            self._list.insert("end", f"  {prefix}{command.title}{detail}{suffix}")
        if self._matches:
            self._list.selection_clear(0, "end")
            self._list.selection_set(0)
            self._list.see(0)

        self._count.configure(text=self._count_text(query, len(matches), len(records)))
        self._schedule_search(query)

    def _count_text(self, query: str, commands: int, records: int) -> str:
        """Describe what the list is currently showing."""
        if not commands and not records:
            if query and len(query) < MIN_SEARCH_LENGTH:
                return "Keep typing to search hosts, incidents and alerts"
            return "Nothing matches that text"
        parts = [f"{commands} command(s)"]
        if records:
            parts.append(f"{records} record(s)")
        elif query and len(query) >= MIN_SEARCH_LENGTH and self._on_search is not None:
            parts.append("searching records...")
        return "  ·  ".join(parts)

    def _schedule_search(self, query: str) -> None:
        """Ask for records once the operator pauses, not on every keystroke."""
        if self._search_job is not None:
            try:
                self.after_cancel(self._search_job)
            except (tk.TclError, ValueError):  # pragma: no cover - already fired
                pass
            self._search_job = None
        if self._on_search is None or len(query) < MIN_SEARCH_LENGTH:
            if self._records:
                self._records = []
                self._records_query = ""
            return
        if query == self._records_query:
            return
        self._search_job = self.after(
            SEARCH_DEBOUNCE_MS, lambda: self._run_search(query)
        )

    def _run_search(self, query: str) -> None:
        """Hand the query to the provider, if it is still the current one."""
        self._search_job = None
        if self._on_search is None or query != self._query.get().strip().lower():
            return
        self._on_search(query)

    # ------------------------------------------------------------------
    # Keyboard
    # ------------------------------------------------------------------
    def _selection(self) -> int:
        """Index of the highlighted entry, or -1."""
        selection = self._list.curselection()
        return int(selection[0]) if selection else -1

    def _move(self, delta: int) -> str:
        """Move the highlight and keep it visible."""
        if not self._matches:
            return "break"
        index = self._selection()
        index = (index + delta) % len(self._matches)
        self._list.selection_clear(0, "end")
        self._list.selection_set(index)
        self._list.see(index)
        return "break"

    def _move_down(self, _event: tk.Event) -> str:
        """Highlight the next entry."""
        return self._move(1)

    def _move_up(self, _event: tk.Event) -> str:
        """Highlight the previous entry."""
        return self._move(-1)

    def _run_selected(self, _event: tk.Event) -> str:
        """Run the highlighted command and close."""
        index = self._selection()
        if 0 <= index < len(self._matches):
            command = self._matches[index]
            self.close()
            command.run()
        return "break"
