"""A right-hand details drawer for investigating without leaving the page.

An analyst working an incident needs to know what a device is *right now* -
not after navigating away, losing the incident, and navigating back. The drawer
slides in over the current screen, shows the record, and closes again, leaving
the page underneath exactly where it was.

It is deliberately not used everywhere. A drawer earns its place where the
question is "what is this row?" mid-investigation; a full screen is still the
right answer for working a queue.

Dismissal follows the conventions an operator already expects: the ✕ button,
``Esc``, or a click on the page behind it.
"""

from __future__ import annotations

import tkinter as tk
from dataclasses import dataclass, field
from tkinter import ttk
from typing import Callable, Sequence

from aethra_sec.ui.theme import PALETTE, Fonts, configure_text_widget, motion_enabled
from aethra_sec.ui.widgets.cards import Card, KeyValueList, ScrollableFrame
from aethra_sec.ui.widgets.chips import SeverityChip

#: Drawer width as a fraction of the screen, clamped to these pixel bounds.
_MIN_WIDTH = 380
_MAX_WIDTH = 560
_WIDTH_FRACTION = 0.42

#: Slide-in animation: short enough to feel instant, long enough to read as
#: motion rather than a jump.
_ANIMATION_STEPS = 7
_ANIMATION_MS = 12


@dataclass
class DrawerSection:
    """One titled block inside the drawer.

    Exactly one of ``rows`` or ``text`` carries the content: a labelled grid for
    facts, monospaced text for evidence and listings.
    """

    title: str
    rows: Sequence[tuple[str, str]] = ()
    text: str = ""
    subtitle: str = ""
    #: Optional row actions, drawn as a button strip under the section.
    actions: Sequence[tuple[str, Callable[[], None]]] = field(default_factory=tuple)


class DetailDrawer(ttk.Frame):
    """A dismissible panel that slides in from the right of a screen."""

    def __init__(self, parent: tk.Misc, fonts: Fonts) -> None:
        """Build the drawer hidden; call :meth:`show` to reveal it."""
        super().__init__(parent, style="TFrame")
        self._parent = parent
        self._fonts = fonts
        self._open = False
        self._width = _MIN_WIDTH
        self._animation: str | None = None
        self._on_close: Callable[[], None] | None = None
        self._outside_binding: str | None = None

        # A left edge in the accent colour separates the drawer from the page
        # behind it without needing a scrim that would hide that page.
        self._edge = tk.Frame(self, background=PALETTE.accent, width=2)
        self._edge.pack(side="left", fill="y")

        body = ttk.Frame(self, style="TFrame")
        body.pack(side="left", fill="both", expand=True)

        header = ttk.Frame(body, style="TFrame", padding=(16, 14, 12, 10))
        header.pack(fill="x")

        title_row = ttk.Frame(header, style="TFrame")
        title_row.pack(fill="x")
        self._title = ttk.Label(title_row, text="", style="DrawerHeading.TLabel")
        self._title.pack(side="left")
        self._close_button = ttk.Button(
            title_row, text="✕", style="Icon.TButton", width=3, command=self.close
        )
        self._close_button.pack(side="right")

        self._subtitle = ttk.Label(
            header, text="", style="DrawerMuted.TLabel", wraplength=460,
            justify="left",
        )
        self._subtitle.pack(anchor="w", pady=(2, 0))

        self._chip_row = ttk.Frame(header, style="TFrame")
        self._chip_row.pack(anchor="w", pady=(8, 0))
        self._chips: list[SeverityChip] = []

        tk.Frame(body, background=PALETTE.border, height=1).pack(fill="x")

        self._scroller = ScrollableFrame(body, padding=14)
        self._scroller.pack(fill="both", expand=True)
        self._content = self._scroller.interior

        self._footer = ttk.Frame(body, style="TFrame", padding=(14, 10))
        self._footer.pack(fill="x", side="bottom")
        self._hint = ttk.Label(
            self._footer, text="Esc closes  ·  click outside closes",
            style="DrawerDim.TLabel",
        )
        self._hint.pack(side="left")
        self._primary: ttk.Button | None = None

    # ------------------------------------------------------------------
    # State
    # ------------------------------------------------------------------
    @property
    def is_open(self) -> bool:
        """True while the drawer is on screen."""
        return self._open

    # ------------------------------------------------------------------
    # Content
    # ------------------------------------------------------------------
    def show(
        self,
        title: str,
        *,
        subtitle: str = "",
        chips: Sequence[tuple[str, str]] = (),
        sections: Sequence[DrawerSection] = (),
        primary: tuple[str, Callable[[], None]] | None = None,
        on_close: Callable[[], None] | None = None,
    ) -> None:
        """Fill the drawer and slide it in.

        Args:
            chips: ``(value, kind)`` pairs - ``kind`` is ``severity``,
                ``status`` or ``state``, matching the table colour vocabulary.
            primary: label and callback for the footer button, normally the
                "open the full screen for this record" escape hatch.
        """
        self._title.configure(text=title)
        self._subtitle.configure(text=subtitle)
        self._on_close = on_close
        self._render_chips(chips)
        self._render_sections(sections)
        self._render_primary(primary)
        self._reveal()

    def _render_chips(self, chips: Sequence[tuple[str, str]]) -> None:
        """Replace the header chip strip."""
        for chip in self._chips:
            chip.destroy()
        self._chips = []
        for value, kind in chips:
            if not value:
                continue
            chip = SeverityChip(
                self._chip_row, value, kind=kind, fonts=self._fonts,
                surface=PALETTE.background,
            )
            chip.pack(side="left", padx=(0, 6))
            self._chips.append(chip)

    def _render_sections(self, sections: Sequence[DrawerSection]) -> None:
        """Rebuild the body from the supplied sections."""
        for child in self._content.winfo_children():
            child.destroy()
        self._scroller._canvas.yview_moveto(0.0)  # noqa: SLF001 - reset the view

        for index, section in enumerate(sections):
            card = Card(
                self._content, section.title, subtitle=section.subtitle,
                fonts=self._fonts, padding=12,
            )
            card.pack(fill="x", pady=(0 if index == 0 else 10, 0))

            if section.rows:
                listing = KeyValueList(card, label_width=18, wraplength=280)
                listing.set_items(list(section.rows))
                listing.pack(fill="x")
            if section.text:
                text = tk.Text(card, wrap="word", height=self._text_height(section.text))
                configure_text_widget(text, self._fonts)
                text.insert("1.0", section.text)
                text.configure(state="disabled")
                text.pack(fill="both", expand=True)
            if section.actions:
                strip = ttk.Frame(card, style="Card.TFrame")
                strip.pack(fill="x", pady=(8, 0))
                for label, action in section.actions:
                    ttk.Button(
                        strip, text=label, style="Tool.TButton", command=action
                    ).pack(side="left", padx=(0, 6))

    @staticmethod
    def _text_height(text: str) -> int:
        """Lines to give a text block, bounded so one section cannot fill it."""
        return max(3, min(18, text.count("\n") + 1))

    def _render_primary(
        self, primary: tuple[str, Callable[[], None]] | None
    ) -> None:
        """Replace the footer's primary action."""
        if self._primary is not None:
            self._primary.destroy()
            self._primary = None
        if primary is None:
            return
        label, action = primary
        self._primary = ttk.Button(
            self._footer, text=label, style="Accent.TButton",
            command=lambda: (self.close(), action()),
        )
        self._primary.pack(side="right")

    # ------------------------------------------------------------------
    # Reveal and dismiss
    # ------------------------------------------------------------------
    def _reveal(self) -> None:
        """Place the drawer and slide it in from the right edge."""
        self._parent.update_idletasks()
        available = max(self._parent.winfo_width(), _MIN_WIDTH + 40)
        self._width = int(
            max(_MIN_WIDTH, min(_MAX_WIDTH, available * _WIDTH_FRACTION))
        )
        self._subtitle.configure(wraplength=self._width - 60)

        if not self._open:
            self._open = True
            self._bind_dismissals()
            if motion_enabled():
                self._animate(step=0)
            else:
                # Reduced motion: place it at its resting position at once.
                self.place(
                    relx=1.0, rely=0, anchor="ne", relheight=1.0,
                    width=self._width, x=0,
                )
                self._animation = None
        else:
            # Already open on another record: stay put and swap the content.
            self.place(relx=1.0, rely=0, anchor="ne", relheight=1.0, width=self._width)
        self.lift()
        self._close_button.focus_set()

    def _animate(self, step: int) -> None:
        """Slide the panel in over a few frames."""
        if not self._open or not self.winfo_exists():
            return
        progress = min(1.0, (step + 1) / _ANIMATION_STEPS)
        # Ease-out: most of the distance is covered early, so it reads as quick.
        eased = 1.0 - (1.0 - progress) ** 3
        offset = int(self._width * (1.0 - eased))
        self.place(
            relx=1.0, rely=0, anchor="ne", relheight=1.0, width=self._width,
            x=offset,
        )
        self.lift()
        if progress < 1.0:
            self._animation = self.after(
                _ANIMATION_MS, lambda: self._animate(step + 1)
            )
        else:
            self._animation = None

    def _bind_dismissals(self) -> None:
        """Esc anywhere, and a click on the page behind, both close the drawer."""
        toplevel = self.winfo_toplevel()
        toplevel.bind("<Escape>", self._on_escape, add="+")
        self._outside_binding = self._parent.bind(
            "<Button-1>", self._on_click_outside, add="+"
        )

    def _on_escape(self, _event: tk.Event) -> str | None:
        """Close on Esc, and let the event through when already closed."""
        if not self._open:
            return None
        self.close()
        return "break"

    def _on_click_outside(self, event: tk.Event) -> None:
        """Close when the click landed on the page rather than in the drawer."""
        if not self._open:
            return
        widget = getattr(event, "widget", None)
        path = str(widget) if widget is not None else ""
        if path.startswith(str(self)):
            return
        self.close()

    def close(self) -> None:
        """Hide the drawer and restore the page's key bindings."""
        if not self._open:
            return
        self._open = False
        if self._animation is not None:
            try:
                self.after_cancel(self._animation)
            except (tk.TclError, ValueError):  # pragma: no cover - already fired
                pass
            self._animation = None
        try:
            self.place_forget()
        except tk.TclError:  # pragma: no cover - window closing
            pass
        if self._outside_binding is not None:
            try:
                self._parent.unbind("<Button-1>", self._outside_binding)
            except tk.TclError:  # pragma: no cover - window closing
                pass
            self._outside_binding = None
        if self._on_close is not None:
            callback, self._on_close = self._on_close, None
            callback()
