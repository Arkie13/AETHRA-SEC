"""Modal dialogs: confirmation, forms and detail views (§109)."""

from __future__ import annotations

import tkinter as tk
from dataclasses import dataclass
from tkinter import ttk
from typing import Any, Callable, Sequence

from aethra_sec.ui.theme import PALETTE, Fonts, configure_text_widget
from aethra_sec.ui.widgets.cards import ScrollableFrame


class ModalDialog(tk.Toplevel):
    """Base modal dialog centred on its parent."""

    def __init__(
        self,
        parent: tk.Misc,
        title: str,
        *,
        width: int = 520,
        height: int = 340,
        resizable: bool = False,
        scrollable: bool = True,
    ) -> None:
        """Create and centre the dialog.

        Args:
            scrollable: give :attr:`body` its own scrolling viewport. On by
                default, because a dialog whose content is longer than its
                window otherwise simply clips it - the operator cannot reach
                the rest, and there is nothing on screen to say anything is
                missing. Pass ``False`` from a dialog that scrolls its own
                content, so the two do not nest.
        """
        super().__init__(parent)
        self.title(title)
        self.configure(background=PALETTE.background)
        self.transient(parent.winfo_toplevel())
        self.resizable(resizable, resizable)
        self.result: Any = None

        # The footer is packed first, against the bottom edge. Tk gives space
        # to earlier children when it runs short, so a footer packed after an
        # expanding body is the first thing squeezed off the window - which is
        # how Save and Cancel became unreachable on a long form.
        self.buttons = ttk.Frame(self, style="TFrame", padding=(18, 0, 18, 16))
        self.buttons.pack(side="bottom", fill="x")

        if scrollable:
            self._scroller: ScrollableFrame | None = ScrollableFrame(
                self, padding=18, autohide=True
            )
            self._scroller.pack(side="top", fill="both", expand=True)
            self.body = self._scroller.interior
        else:
            self._scroller = None
            self.body = ttk.Frame(self, style="TFrame", padding=18)
            self.body.pack(side="top", fill="both", expand=True)

        self.update_idletasks()
        self._centre(width, height)
        self.protocol("WM_DELETE_WINDOW", self.cancel)
        self.bind("<Escape>", lambda _event: self.cancel())

    def _centre(self, width: int, height: int) -> None:
        """Position the dialog over the parent window, inside the screen.

        The requested height is a preference, not a promise: a form with many
        fields asked for more than the display was tall, so it opened with its
        lower edge - and its buttons - past the bottom of the screen. What is
        placed here is the smaller of what the dialog wants and what the
        display can actually show.
        """
        parent = self.master.winfo_toplevel()
        margin = 80  # taskbar, title bar and a little breathing room
        width = max(320, min(width, self.winfo_screenwidth() - 40))
        height = max(200, min(height, self.winfo_screenheight() - margin))
        try:
            x = parent.winfo_rootx() + max(0, (parent.winfo_width() - width) // 2)
            y = parent.winfo_rooty() + max(0, (parent.winfo_height() - height) // 3)
        except tk.TclError:  # pragma: no cover - parent not yet mapped
            x = y = 100
        # Nudge back on screen if centring would push an edge off it.
        x = max(0, min(x, self.winfo_screenwidth() - width))
        y = max(0, min(y, self.winfo_screenheight() - height - margin // 2))
        self.geometry(f"{width}x{height}+{x}+{y}")

    def show(self) -> Any:
        """Display modally and return :attr:`result`."""
        self.grab_set()
        self.wait_window()
        return self.result

    def cancel(self) -> None:
        """Dismiss without a result."""
        self.result = None
        self.destroy()


class ConfirmDialog(ModalDialog):
    """A confirmation prompt for potentially disruptive operations (§109)."""

    def __init__(
        self,
        parent: tk.Misc,
        title: str,
        message: str,
        *,
        detail: str = "",
        confirm_label: str = "Confirm",
        danger: bool = False,
    ) -> None:
        """Create the prompt."""
        super().__init__(parent, title, width=480, height=230)
        ttk.Label(
            self.body, text=message, style="Heading.TLabel", wraplength=430,
            justify="left",
        ).pack(anchor="w")
        if detail:
            ttk.Label(
                self.body, text=detail, style="Muted.TLabel", wraplength=430,
                justify="left",
            ).pack(anchor="w", pady=(10, 0))

        ttk.Button(
            self.buttons, text="Cancel", style="Ghost.TButton", command=self.cancel
        ).pack(side="right")
        ttk.Button(
            self.buttons,
            text=confirm_label,
            style="Danger.TButton" if danger else "Accent.TButton",
            command=self._confirm,
        ).pack(side="right", padx=(0, 8))

    def _confirm(self) -> None:
        """Accept and close."""
        self.result = True
        self.destroy()


def confirm(
    parent: tk.Misc,
    title: str,
    message: str,
    *,
    detail: str = "",
    confirm_label: str = "Confirm",
    danger: bool = False,
) -> bool:
    """Show a confirmation dialog and return the operator's choice."""
    return bool(
        ConfirmDialog(
            parent, title, message, detail=detail,
            confirm_label=confirm_label, danger=danger,
        ).show()
    )


class MessageDialog(ModalDialog):
    """An informational dialog with selectable text."""

    def __init__(
        self,
        parent: tk.Misc,
        title: str,
        message: str,
        *,
        detail: str = "",
        fonts: Fonts | None = None,
        width: int = 620,
        height: int = 400,
        mono: bool = False,
    ) -> None:
        """Create the dialog."""
        super().__init__(parent, title, width=width, height=height, resizable=True)
        ttk.Label(
            self.body, text=message, style="Heading.TLabel", wraplength=width - 70,
            justify="left",
        ).pack(anchor="w", pady=(0, 10))

        if detail:
            container = ttk.Frame(self.body, style="TFrame")
            container.pack(fill="both", expand=True)
            text = tk.Text(container, height=12, wrap="word")
            if fonts:
                configure_text_widget(text, fonts, mono=mono)
            scrollbar = ttk.Scrollbar(container, orient="vertical", command=text.yview)
            text.configure(yscrollcommand=scrollbar.set)
            text.insert("1.0", detail)
            text.configure(state="disabled")
            text.pack(side="left", fill="both", expand=True)
            scrollbar.pack(side="right", fill="y")

        ttk.Button(
            self.buttons, text="Close", style="Accent.TButton", command=self.cancel
        ).pack(side="right")


def show_message(
    parent: tk.Misc,
    title: str,
    message: str,
    *,
    detail: str = "",
    fonts: Fonts | None = None,
    mono: bool = False,
) -> None:
    """Show an informational dialog."""
    MessageDialog(
        parent, title, message, detail=detail, fonts=fonts, mono=mono
    ).show()


def show_error(
    parent: tk.Misc, title: str, message: str, *, detail: str = "",
    fonts: Fonts | None = None,
) -> None:
    """Show an error dialog carrying the real, actionable message."""
    MessageDialog(parent, title, message, detail=detail, fonts=fonts).show()


class FormField:
    """One field in a :class:`FormDialog`."""

    def __init__(
        self,
        key: str,
        label: str,
        *,
        kind: str = "text",
        value: Any = "",
        options: Sequence[str] = (),
        required: bool = False,
        help_text: str = "",
        width: int = 34,
    ) -> None:
        """Describe a form field.

        Args:
            kind: ``text``, ``password``, ``choice``, ``bool``, ``int`` or
                ``multiline``.
        """
        self.key = key
        self.label = label
        self.kind = kind
        self.value = value
        self.options = tuple(options)
        self.required = required
        self.help_text = help_text
        self.width = width
        self.variable: Any = None
        self.widget: Any = None


class FormDialog(ModalDialog):
    """A generic form dialog used for user, mitigation and settings editing."""

    def __init__(
        self,
        parent: tk.Misc,
        title: str,
        fields: Sequence[FormField],
        *,
        fonts: Fonts | None = None,
        submit_label: str = "Save",
        intro: str = "",
        width: int = 620,
        validator: Callable[[dict[str, Any]], str] | None = None,
    ) -> None:
        """Create the form."""
        multiline_count = sum(1 for f in fields if f.kind == "multiline")
        height = min(
            760,
            200 + len(fields) * 52 + multiline_count * 90 + (40 if intro else 0),
        )
        super().__init__(parent, title, width=width, height=height, resizable=True)
        self._fields = list(fields)
        self._validator = validator
        self._fonts = fonts
        self._error = ttk.Label(
            self.body, text="", style="CriticalBg.TLabel", wraplength=width - 70,
            justify="left",
        )

        if intro:
            ttk.Label(
                self.body, text=intro, style="Muted.TLabel",
                wraplength=width - 70, justify="left",
            ).pack(anchor="w", pady=(0, 12))

        canvas_host = ttk.Frame(self.body, style="TFrame")
        canvas_host.pack(fill="both", expand=True)
        for field in self._fields:
            self._build_field(canvas_host, field)

        self._error.pack(anchor="w", pady=(10, 0))
        ttk.Button(
            self.buttons, text="Cancel", style="Ghost.TButton", command=self.cancel
        ).pack(side="right")
        ttk.Button(
            self.buttons, text=submit_label, style="Accent.TButton",
            command=self._submit,
        ).pack(side="right", padx=(0, 8))

    def _build_field(self, parent: tk.Misc, field: FormField) -> None:
        """Create the widgets for one field."""
        row = ttk.Frame(parent, style="TFrame")
        row.pack(fill="x", pady=5)
        label_text = f"{field.label}{' *' if field.required else ''}"
        ttk.Label(row, text=label_text, style="Muted.TLabel", width=22, anchor="w").pack(
            side="left", anchor="n", pady=3
        )

        if field.kind == "bool":
            field.variable = tk.BooleanVar(value=bool(field.value))
            field.widget = ttk.Checkbutton(row, variable=field.variable)
            field.widget.pack(side="left", pady=3)
        elif field.kind == "choice":
            field.variable = tk.StringVar(value=str(field.value))
            field.widget = ttk.Combobox(
                row, textvariable=field.variable, values=list(field.options),
                state="readonly", width=field.width,
            )
            field.widget.pack(side="left", fill="x", expand=True)
        elif field.kind == "multiline":
            container = ttk.Frame(row, style="TFrame")
            container.pack(side="left", fill="both", expand=True)
            field.widget = tk.Text(container, height=5, wrap="word")
            if self._fonts:
                configure_text_widget(field.widget, self._fonts)
            field.widget.insert("1.0", str(field.value or ""))
            field.widget.pack(fill="both", expand=True)
        else:
            field.variable = tk.StringVar(value=str(field.value))
            field.widget = ttk.Entry(
                row, textvariable=field.variable, width=field.width,
                show="*" if field.kind == "password" else "",
            )
            field.widget.pack(side="left", fill="x", expand=True)

        if field.help_text:
            ttk.Label(
                parent, text=field.help_text, style="Muted.TLabel",
                wraplength=520, justify="left",
            ).pack(anchor="w", padx=(184, 0), pady=(0, 4))

    def _collect(self) -> dict[str, Any]:
        """Read every field's current value."""
        values: dict[str, Any] = {}
        for field in self._fields:
            if field.kind == "multiline":
                values[field.key] = field.widget.get("1.0", "end").strip()
            elif field.kind == "bool":
                values[field.key] = bool(field.variable.get())
            elif field.kind == "int":
                raw = str(field.variable.get()).strip()
                values[field.key] = raw
            else:
                values[field.key] = str(field.variable.get()).strip()
        return values

    def _submit(self) -> None:
        """Validate and close, or show the validation error inline."""
        values = self._collect()
        for field in self._fields:
            if field.required and not str(values.get(field.key, "")).strip():
                self._error.configure(text=f"{field.label} is required.")
                return
        if self._validator is not None:
            message = self._validator(values)
            if message:
                self._error.configure(text=message)
                return
        self.result = values
        self.destroy()


@dataclass(frozen=True)
class DetailSection:
    """One block in a :class:`DetailDialog`.

    A section can carry key/value rows, free text, or both. ``tone`` picks the
    heading colour so one block can be set apart from the rest without a
    second dialog class, and ``collapsed`` hides the body behind a toggle -
    used for raw sensor evidence, which must stay available in full without
    pushing the analysis off the first screenful.
    """

    heading: str
    body: str = ""
    rows: Sequence[tuple[str, str]] = ()
    tone: str = "accent"
    collapsed: bool = False


class DetailDialog(ModalDialog):
    """A read-only detail view with key/value rows and free text sections."""

    def __init__(
        self,
        parent: tk.Misc,
        title: str,
        rows: Sequence[tuple[str, str]],
        *,
        sections: Sequence[tuple[str, str] | DetailSection] = (),
        actions: Sequence[tuple[str, Callable[[], None]]] = (),
        fonts: Fonts | None = None,
        width: int = 760,
        height: int = 560,
    ) -> None:
        """Create the detail view.

        Args:
            sections: ``(heading, body)`` pairs, or :class:`DetailSection`
                instances where a block needs rows, its own tone or a
                collapsed body.
            actions: extra buttons beside Close, as ``(label, callback)``.
                Used for links out of the dialog, such as opening the
                mitigation entry an alert resolved to.
        """
        super().__init__(
            parent, title, width=width, height=height, resizable=True,
            scrollable=False,
        )
        text = tk.Text(self.body, wrap="word")
        if fonts:
            configure_text_widget(text, fonts)
        scrollbar = ttk.Scrollbar(self.body, orient="vertical", command=text.yview)
        text.configure(yscrollcommand=scrollbar.set)
        text.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        bold = fonts.body_bold if fonts else ("TkDefaultFont", 10, "bold")
        text.tag_configure("key", foreground=PALETTE.text_muted)
        text.tag_configure(
            "heading", foreground=PALETTE.accent, font=bold, spacing1=8, spacing3=4,
        )
        # A second heading tone, so a block an analyst is expected to act on
        # reads differently from the record around it.
        text.tag_configure(
            "heading_action", foreground=PALETTE.ok, font=bold, spacing1=10,
            spacing3=4,
        )
        text.tag_configure(
            "heading_warn", foreground=PALETTE.high, font=bold, spacing1=10,
            spacing3=4,
        )
        text.tag_configure("toggle", foreground=PALETTE.accent, underline=True)

        def write_rows(pairs: Sequence[tuple[str, str]]) -> None:
            for key, value in pairs:
                text.insert("end", f"{key}: ", "key")
                text.insert("end", f"{value}\n")

        write_rows(rows)

        self._collapsed: dict[str, bool] = {}
        for index, entry in enumerate(sections):
            section = (
                entry
                if isinstance(entry, DetailSection)
                else DetailSection(heading=entry[0], body=entry[1])
            )
            tag = {
                "action": "heading_action",
                "warn": "heading_warn",
            }.get(section.tone, "heading")
            text.insert("end", f"\n{section.heading}\n", tag)
            if section.collapsed:
                self._add_toggle(text, index, section)
            else:
                write_rows(section.rows)
                if section.body:
                    text.insert("end", f"{section.body}\n")
        text.configure(state="disabled")
        self._text = text

        ttk.Button(
            self.buttons, text="Close", style="Accent.TButton", command=self.cancel
        ).pack(side="right")
        for label, command in actions:
            ttk.Button(
                self.buttons, text=label, style="Ghost.TButton", command=command
            ).pack(side="right", padx=(0, 8))

    def _add_toggle(
        self, text: tk.Text, index: int, section: DetailSection
    ) -> None:
        """Render a collapsed section behind a clickable show/hide line.

        The body is inserted in full and elided rather than withheld, so the
        evidence is always present in the widget - expanding it is a display
        change, and a copy of the whole dialog still carries it.
        """
        name = f"collapsed{index}"
        show = f"show{index}"
        hide = f"hide{index}"
        lines = section.body.count("\n") + 1 if section.body else 0
        counted = f"{lines} line{'' if lines == 1 else 's'}"

        # Both labels are inserted once and one of them is always elided, so
        # toggling never rewrites the widget - no index arithmetic to drift.
        text.insert("end", f"[+] Show ({counted})\n", ("toggle", show))
        text.insert("end", f"[-] Hide ({counted})\n", ("toggle", hide))
        for key, value in section.rows:
            text.insert("end", f"{key}: ", ("key", name))
            text.insert("end", f"{value}\n", name)
        if section.body:
            text.insert("end", f"{section.body}\n", name)
        text.tag_configure(hide, elide=True)
        text.tag_configure(name, elide=True)
        self._collapsed[name] = True

        def toggle(_event: tk.Event) -> str:
            collapsed = not self._collapsed[name]
            self._collapsed[name] = collapsed
            text.tag_configure(name, elide=collapsed)
            text.tag_configure(show, elide=not collapsed)
            text.tag_configure(hide, elide=collapsed)
            return "break"

        text.tag_bind(show, "<Button-1>", toggle)
        text.tag_bind(hide, "<Button-1>", toggle)

    def is_collapsed(self, index: int = 0) -> bool:
        """Whether a collapsed section is currently hidden (used by tests)."""
        return self._collapsed.get(f"collapsed{index}", False)

    def toggle_section(self, index: int = 0) -> None:
        """Expand or collapse a section without a mouse (used by tests)."""
        name = f"collapsed{index}"
        if name not in self._collapsed:
            return
        collapsed = not self._collapsed[name]
        self._collapsed[name] = collapsed
        self._text.tag_configure(name, elide=collapsed)
        self._text.tag_configure(f"show{index}", elide=not collapsed)
        self._text.tag_configure(f"hide{index}", elide=collapsed)
