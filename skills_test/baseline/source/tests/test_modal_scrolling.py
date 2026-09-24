"""Modals must stay usable when their content is long (§52).

Every dialog was sized to a fixed height and simply clipped anything taller:
the operator could not reach the rest of a long message, a form with many
fields lost its Save and Cancel buttons off the bottom edge, and a form sized
past the height of the display opened partly off-screen.

These tests open real dialogs with content longer than they can show and check
what the operator could actually reach.
"""

from __future__ import annotations

import tkinter as tk

import pytest

from aethra_sec.ui.theme import apply_theme
from aethra_sec.ui.widgets.dialogs import (
    ConfirmDialog,
    DetailDialog,
    FormDialog,
    FormField,
    MessageDialog,
)

LONG = "This paragraph exists to overflow the dialog. " * 60


@pytest.fixture(scope="module")
def tk_root():
    """A real Tk root, skipped where no display exists."""
    try:
        root = tk.Tk()
    except tk.TclError as exc:  # pragma: no cover - headless CI
        pytest.skip(f"no display: {exc}")
    root.geometry("1400x900+40+40")
    fonts = apply_theme(root)
    root.update()
    root.fonts = fonts  # type: ignore[attr-defined]
    yield root
    root.destroy()


def _scrolls(widget: tk.Misc) -> bool:
    """True when something in this subtree can actually be scrolled."""
    if widget.winfo_class() in ("Canvas", "Text", "Listbox", "Treeview"):
        try:
            first, last = widget.yview()  # type: ignore[attr-defined]
            if last - first < 0.999:
                return True
        except (tk.TclError, AttributeError, ValueError):
            pass
    return any(_scrolls(child) for child in widget.winfo_children())


def _open(dialog: tk.Toplevel) -> tk.Toplevel:
    """Realise the dialog so its geometry is measurable."""
    dialog.update_idletasks()
    dialog.update()
    return dialog


class TestLongContentStaysReachable:
    """Nothing may be clipped away with no way to get to it."""

    def test_a_long_confirmation_scrolls(self, tk_root: tk.Tk) -> None:
        dialog = _open(ConfirmDialog(tk_root, "Confirm", LONG, detail=LONG))
        try:
            assert _scrolls(dialog), (
                "a confirmation longer than its window clips with no scrollbar"
            )
        finally:
            dialog.destroy()

    def test_a_long_message_scrolls(self, tk_root: tk.Tk) -> None:
        dialog = _open(MessageDialog(tk_root, "Message", LONG))
        try:
            assert _scrolls(dialog)
        finally:
            dialog.destroy()

    def test_a_long_form_scrolls(self, tk_root: tk.Tk) -> None:
        fields = [
            FormField(key=f"f{i}", label=f"Field {i}", value=f"value {i}")
            for i in range(24)
        ]
        dialog = _open(
            FormDialog(tk_root, "Form", fields, fonts=tk_root.fonts, intro=LONG[:400])
        )
        try:
            assert _scrolls(dialog)
        finally:
            dialog.destroy()

    def test_a_long_detail_view_scrolls(self, tk_root: tk.Tk) -> None:
        dialog = _open(
            DetailDialog(
                tk_root,
                "Detail",
                [(f"Field {i}", f"value {i}") for i in range(30)],
                sections=[("Notes", LONG)],
                fonts=tk_root.fonts,
            )
        )
        try:
            assert _scrolls(dialog)
        finally:
            dialog.destroy()


class TestTheFooterIsAlwaysReachable:
    """Save and Cancel are the point of the dialog."""

    @pytest.mark.parametrize(
        "factory",
        [
            lambda root: ConfirmDialog(root, "Confirm", LONG, detail=LONG),
            lambda root: MessageDialog(root, "Message", LONG),
            lambda root: FormDialog(
                root,
                "Form",
                [FormField(key=f"f{i}", label=f"Field {i}") for i in range(24)],
                fonts=root.fonts,
            ),
        ],
        ids=["confirm", "message", "form"],
    )
    def test_the_buttons_sit_inside_the_window(self, tk_root: tk.Tk, factory) -> None:
        dialog = _open(factory(tk_root))
        try:
            footer = dialog.buttons  # type: ignore[attr-defined]
            assert footer.winfo_ismapped(), "the footer was never drawn"
            top = dialog.winfo_rooty()
            bottom = footer.winfo_rooty() + footer.winfo_height()
            assert bottom <= top + dialog.winfo_height() + 2, (
                "the footer buttons are below the window's bottom edge"
            )
        finally:
            dialog.destroy()


class TestTheWindowFitsTheDisplay:
    """A dialog taller than the screen puts its own buttons out of reach."""

    def test_a_tall_form_is_clamped_to_the_screen(self, tk_root: tk.Tk) -> None:
        fields = [
            FormField(key=f"f{i}", label=f"Field {i}", kind="multiline")
            for i in range(20)
        ]
        dialog = _open(FormDialog(tk_root, "Tall form", fields, fonts=tk_root.fonts))
        try:
            bottom = dialog.winfo_rooty() + dialog.winfo_height()
            assert bottom <= dialog.winfo_screenheight(), (
                f"the dialog ends at {bottom}px on a "
                f"{dialog.winfo_screenheight()}px screen"
            )
        finally:
            dialog.destroy()


class TestKeyboardDismissal:
    """ESC closes, on every dialog."""

    @pytest.mark.parametrize(
        "factory",
        [
            lambda root: ConfirmDialog(root, "Confirm", "short"),
            lambda root: MessageDialog(root, "Message", "short"),
            lambda root: DetailDialog(root, "Detail", [("a", "b")], fonts=root.fonts),
            lambda root: FormDialog(
                root, "Form", [FormField(key="a", label="A")], fonts=root.fonts
            ),
        ],
        ids=["confirm", "message", "detail", "form"],
    )
    def test_escape_dismisses(self, tk_root: tk.Tk, factory) -> None:
        dialog = _open(factory(tk_root))
        dialog.focus_force()
        dialog.update()
        dialog.event_generate("<Escape>", when="now")
        dialog.update()
        assert not dialog.winfo_exists(), "ESC did not close the dialog"


class TestScrollbarsDoNotNest:
    """One body of content gets one scrollbar, not two."""

    @pytest.mark.parametrize(
        "factory",
        [
            lambda root: DetailDialog(
                root, "Detail", [("a", "b")], sections=[("Notes", LONG)],
                fonts=root.fonts,
            ),
        ],
        ids=["detail"],
    )
    def test_a_self_scrolling_dialog_gets_no_outer_viewport(
        self, tk_root: tk.Tk, factory
    ) -> None:
        """A Text that already scrolls must not sit inside a scrolling canvas."""
        dialog = _open(factory(tk_root))
        try:
            canvases = []

            def walk(widget: tk.Misc) -> None:
                if widget.winfo_class() == "Canvas":
                    canvases.append(widget)
                for child in widget.winfo_children():
                    walk(child)

            walk(dialog)
            assert not canvases, (
                "a dialog that scrolls its own content was given a second viewport"
            )
        finally:
            dialog.destroy()
