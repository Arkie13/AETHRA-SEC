"""Modal dialogs: confirmation, forms and detail views (§109)."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Any, Callable, Sequence

from aethra_sec.ui.theme import PALETTE, Fonts, configure_text_widget


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
    ) -> None:
        """Create and centre the dialog."""
        super().__init__(parent)
        self.title(title)
        self.configure(background=PALETTE.background)
        self.transient(parent.winfo_toplevel())
        self.resizable(resizable, resizable)
        self.result: Any = None

        self.body = ttk.Frame(self, style="TFrame", padding=18)
        self.body.pack(fill="both", expand=True)
        self.buttons = ttk.Frame(self, style="TFrame", padding=(18, 0, 18, 16))
        self.buttons.pack(fill="x")

        self.update_idletasks()
        self._centre(width, height)
        self.protocol("WM_DELETE_WINDOW", self.cancel)
        self.bind("<Escape>", lambda _event: self.cancel())

    def _centre(self, width: int, height: int) -> None:
        """Position the dialog over the parent window."""
        parent = self.master.winfo_toplevel()
        try:
            x = parent.winfo_rootx() + max(0, (parent.winfo_width() - width) // 2)
            y = parent.winfo_rooty() + max(0, (parent.winfo_height() - height) // 3)
        except tk.TclError:  # pragma: no cover - parent not yet mapped
            x = y = 100
        self.geometry(f"{width}x{height}+{max(0, x)}+{max(0, y)}")

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
            ).pack(anchor="w", pady=(16, 0))

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

        self._error.pack(anchor="w", pady=(16, 0))
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


class DetailDialog(ModalDialog):
    """A read-only detail view with key/value rows and free text sections."""

    def __init__(
        self,
        parent: tk.Misc,
        title: str,
        rows: Sequence[tuple[str, str]],
        *,
        sections: Sequence[tuple[str, str]] = (),
        fonts: Fonts | None = None,
        width: int = 760,
        height: int = 560,
    ) -> None:
        """Create the detail view."""
        super().__init__(parent, title, width=width, height=height, resizable=True)
        text = tk.Text(self.body, wrap="word")
        if fonts:
            configure_text_widget(text, fonts)
        scrollbar = ttk.Scrollbar(self.body, orient="vertical", command=text.yview)
        text.configure(yscrollcommand=scrollbar.set)
        text.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        text.tag_configure("key", foreground=PALETTE.text_muted)
        text.tag_configure(
            "heading", foreground=PALETTE.accent,
            font=(fonts.body_bold if fonts else ("TkDefaultFont", 10, "bold")),
            spacing1=8, spacing3=4,
        )

        for key, value in rows:
            text.insert("end", f"{key}: ", "key")
            text.insert("end", f"{value}\n")
        for heading, body in sections:
            text.insert("end", f"\n{heading}\n", "heading")
            text.insert("end", f"{body}\n")
        text.configure(state="disabled")

        ttk.Button(
            self.buttons, text="Close", style="Accent.TButton", command=self.cancel
        ).pack(side="right")
