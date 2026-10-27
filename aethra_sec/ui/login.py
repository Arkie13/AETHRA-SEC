"""Login window (§62).

Behaviour that matters for security:

* the same message is shown for an unknown username and a wrong password, so
  account existence is never disclosed;
* authentication runs on a worker thread - Argon2 verification is deliberately
  slow, and blocking the Tk thread would freeze the window;
* subsystem status is shown truthfully before sign-in, so an operator can see
  the database is offline rather than discovering it after a failed login.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Callable

from aethra_sec import runtime
from aethra_sec.core.application import ApplicationContext, StartupReport
from aethra_sec.core.errors import AethraError, user_facing
from aethra_sec.core.session import Session
from aethra_sec.ui import dispatch
from datetime import datetime, timedelta
from pathlib import Path

from aethra_sec.ui.brand import (
    LOGO_CANVAS,
    LOGO_LETTER,
    LOGO_OUTLINE_WIDTH,
    flat_logo_points,
)
from aethra_sec.ui.state import KEY_THEME, UiState
from aethra_sec.security.lockout import format_remaining
from aethra_sec.utils.timeutil import utcnow
from aethra_sec.ui.theme import (
    DEFAULT_THEME,
    PALETTE,
    Fonts,
    apply_theme,
    set_theme,
)
from aethra_sec.utils.logging import get_logger
from aethra_sec.version import (
    APP_FULL_NAME,
    APP_NAME,
    APP_VERSION,
    AUTHORIZED_USE_NOTICE,
)

LOGGER = get_logger("ui.login")

#: Whether the sign-in form should pre-fill the last username.
KEY_REMEMBER = "login.remember_username"

#: The username to pre-fill. A password is never stored.
KEY_REMEMBERED_USER = "login.username"


class LoginWindow(tk.Toplevel):
    """Modal sign-in window shown before the main console."""

    def __init__(
        self,
        master: tk.Tk,
        context: ApplicationContext,
        fonts: Fonts,
        on_success: Callable[[Session], None],
    ) -> None:
        """Create the login window."""
        super().__init__(master)
        self.context = context
        self.fonts = fonts
        self._on_success = on_success
        self._busy = False
        #: Local mirror of the server's lock, for the countdown only. The
        #: server is asked again before every attempt, so stopping this clock
        #: buys nothing.
        self._lock_deadline: datetime | None = None
        self._lock_job: str | None = None
        self._state = UiState(context.settings.log_dir)

        # Sign-in runs on a worker thread, so the bridge that carries its
        # result back to the Tk thread must exist before the form is usable.
        dispatch.ensure(master)

        self.title(f"{APP_NAME} - Sign in")
        self.configure(background=PALETTE.background)
        self.resizable(False, False)
        self.protocol("WM_DELETE_WINDOW", self._quit)

        self._build()
        self._centre()
        self.after(50, self._show_startup_state)
        # A lock outlives this window. Re-opening the application, or simply
        # typing the name again, shows the remaining time rather than a fresh
        # form that would accept an attempt the server is going to refuse.
        self.after(120, self._refresh_lock_state)
        self._username.trace_add("write", lambda *_a: self._refresh_lock_state())

    # ------------------------------------------------------------------
    # Layout
    # ------------------------------------------------------------------
    def _build(self) -> None:
        """Construct the window contents."""
        container = ttk.Frame(self, style="Auth.TFrame")
        container.pack(fill="both", expand=True)
        self._build_brand_panel(container)
        self._build_form_panel(container)

        self._username_entry.focus_set()
        for widget in (self._username_entry, self._password_entry):
            widget.bind("<Return>", lambda _event: self._submit_login())
            widget.bind("<KeyRelease>", self._on_key)

    # ------------------------------------------------------------------
    def _build_brand_panel(self, parent: tk.Misc) -> None:
        """The identity column: who this is, and what it is watching.

        The old panel listed the tools the product is built from, which is a
        brochure. What an operator wants to know before signing in is whether
        the thing is actually running, so the panel carries live subsystem
        state instead - the same probe results the console shows afterwards.
        """
        brand = ttk.Frame(parent, style="AuthBrand.TFrame", width=380)
        brand.pack(side="left", fill="y")
        brand.pack_propagate(False)

        # A drawn mark rather than an image file, so there is no asset to ship
        # and it scales with the window on any display.
        mark = tk.Canvas(
            brand, width=64, height=64, background=PALETTE.surface_alt,
            highlightthickness=0, borderwidth=0,
        )
        mark.place(x=44, y=56)
        # The same numbers the Windows icon is rendered from, so the shortcut
        # on the desktop cannot drift away from what the screen shows.
        mark.create_polygon(
            *flat_logo_points(LOGO_CANVAS),
            fill=PALETTE.accent_soft, outline=PALETTE.accent,
            width=LOGO_OUTLINE_WIDTH,
        )
        mark.create_text(
            LOGO_CANVAS / 2, LOGO_CANVAS / 2, text=LOGO_LETTER,
            fill=PALETTE.accent, font=(self.fonts.family, 24, "bold"),
        )

        body = ttk.Frame(brand, style="AuthBrand.TFrame", padding=(44, 0))
        body.place(x=0, y=150, relwidth=1)
        ttk.Label(body, text=APP_NAME, style="AuthWordmark.TLabel").pack(anchor="w")
        ttk.Label(
            body, text="SECURITY OPERATIONS CONSOLE", style="AuthTagline.TLabel"
        ).pack(anchor="w", pady=(2, 0))
        tk.Frame(body, background=PALETTE.border_strong, height=1).pack(
            fill="x", pady=(22, 20)
        )
        ttk.Label(
            body,
            text=(
                "Continuous traffic analysis, intrusion detection and "
                "vulnerability assessment, in one place you can act from."
            ),
            style="AuthBrandBody.TLabel", wraplength=292, justify="left",
        ).pack(anchor="w")

        # Live subsystem readout, filled in by _show_startup_state.
        self._subsystem_frame = ttk.Frame(body, style="AuthBrand.TFrame")
        self._subsystem_frame.pack(anchor="w", fill="x", pady=(26, 0))
        self._subsystem_rows: dict[str, ttk.Label] = {}
        self._subsystem_dots: dict[str, tk.Canvas] = {}
        for key, label in (
            ("database", "Database"),
            ("schema", "Schema"),
        ):
            row = ttk.Frame(self._subsystem_frame, style="AuthBrand.TFrame")
            row.pack(anchor="w", fill="x", pady=3)
            dot = tk.Canvas(
                row, width=8, height=8, background=PALETTE.surface_alt,
                highlightthickness=0, borderwidth=0,
            )
            dot.create_oval(1, 1, 7, 7, fill=PALETTE.offline, outline="")
            dot.pack(side="left", padx=(0, 10))
            ttk.Label(
                row, text=label, style="AuthBrandDim.TLabel", width=11
            ).pack(side="left")
            value = ttk.Label(
                row, text="checking...", style="AuthStatus.TLabel",
                wraplength=176, justify="left",
            )
            value.pack(side="left", fill="x", expand=True)
            self._subsystem_rows[key] = value
            self._subsystem_dots[key] = dot

        footer = ttk.Frame(brand, style="AuthBrand.TFrame", padding=(44, 0))
        footer.place(relx=0, rely=1.0, y=-40, relwidth=1)
        ttk.Label(
            footer, text=f"Version {APP_VERSION}", style="AuthBrandDim.TLabel"
        ).pack(anchor="w")

    # ------------------------------------------------------------------
    def _build_form_panel(self, parent: tk.Misc) -> None:
        """The credential column."""
        panel = ttk.Frame(parent, style="AuthPanel.TFrame")
        panel.pack(side="left", fill="both", expand=True)

        form = ttk.Frame(panel, style="AuthPanel.TFrame", padding=(52, 0))
        form.pack(side="top", fill="both", expand=True, pady=(40, 0))
        # Kept so the verification step can hide the credential fields and
        # present one question at a time.
        self._form = form

        ttk.Label(form, text="Sign in", style="AuthTitle.TLabel").pack(anchor="w")
        ttk.Label(
            form,
            text="Authorised operators only. Every sign-in is recorded.",
            style="AuthSubtitle.TLabel",
        ).pack(anchor="w", pady=(6, 0))

        # --- lockout banner, shown only while sign-in is actually refused --
        self._lock_frame = ttk.Frame(form, style="AuthError.TFrame", padding=(12, 10))
        self._lock_title = ttk.Label(
            self._lock_frame, text="ACCOUNT TEMPORARILY LOCKED",
            style="AuthErrorText.TLabel",
        )
        self._lock_title.pack(anchor="w")
        ttk.Label(
            self._lock_frame,
            text="Too many unsuccessful login attempts.",
            style="AuthNote.TLabel", wraplength=380, justify="left",
        ).pack(anchor="w", pady=(4, 0))
        self._lock_countdown = ttk.Label(
            self._lock_frame, text="", style="AuthErrorText.TLabel",
        )
        self._lock_countdown.pack(anchor="w", pady=(6, 0))

        # --- error / message band, hidden until it has something to say ---
        self._message_frame = ttk.Frame(form, style="AuthError.TFrame", padding=(12, 9))
        self._message = ttk.Label(
            self._message_frame, text="", style="AuthErrorText.TLabel",
            wraplength=380, justify="left",
        )
        self._message.pack(anchor="w")

        # --- username -----------------------------------------------------
        ttk.Label(form, text="USERNAME", style="AuthLabel.TLabel").pack(
            anchor="w", pady=(26, 6)
        )
        self._username = tk.StringVar()
        self._username_entry, username_box = self._field(form, self._username)

        # --- password, with a reveal control ------------------------------
        ttk.Label(form, text="PASSWORD", style="AuthLabel.TLabel").pack(
            anchor="w", pady=(16, 6)
        )
        self._password = tk.StringVar()
        self._password_entry, password_box = self._field(
            form, self._password, secret=True
        )
        self._reveal = ttk.Button(
            password_box, text="show", style="AuthReveal.TButton", width=5,
            command=self._toggle_reveal,
        )
        self._reveal.pack(side="right", padx=(0, 6))

        # --- caps lock, remember me --------------------------------------
        self._caps_label = ttk.Label(form, text="", style="AuthNote.TLabel")
        self._caps_label.pack(anchor="w", pady=(6, 0))

        options = ttk.Frame(form, style="AuthPanel.TFrame")
        options.pack(fill="x", pady=(10, 0))
        self._remember = tk.BooleanVar(value=bool(self._state.get_bool(KEY_REMEMBER)))
        ttk.Checkbutton(
            options, text="Remember my username", variable=self._remember,
            style="AuthCheck.TCheckbutton",
        ).pack(side="left")
        forgot = ttk.Label(options, text="Forgot password?", style="AuthLink.TLabel")
        forgot.pack(side="right")
        forgot.bind("<Button-1>", lambda _e: self._open_recovery())
        forgot.configure(cursor="hand2")

        # --- submit -------------------------------------------------------
        self._submit = ttk.Button(
            form, text="Sign in", style="AuthPrimary.TButton",
            command=self._submit_login,
        )
        self._submit.pack(fill="x", pady=(22, 0))

        recovery = ttk.Label(
            form, text="I already have a recovery code", style="AuthLink.TLabel"
        )
        recovery.pack(anchor="w", pady=(14, 0))
        recovery.bind("<Button-1>", lambda _e: self._open_recovery(start_tab=1))
        recovery.configure(cursor="hand2")

        ttk.Label(
            form,
            text=(
                "A reset is queued for administrator review. Your password does "
                "not change until an administrator approves it and you use the "
                "one-time code they issue."
            ),
            style="AuthNote.TLabel", wraplength=420, justify="left",
        ).pack(anchor="w", pady=(6, 0))

        # The authorisation notice belongs at the bottom of the window, not in
        # the middle of the form where it competed with the fields.
        notice = ttk.Frame(panel, style="AuthPanel.TFrame", padding=(52, 14))
        notice.pack(side="bottom", fill="x")
        tk.Frame(notice, background=PALETTE.border, height=1).pack(
            fill="x", pady=(0, 12)
        )
        ttk.Label(
            notice, text=AUTHORIZED_USE_NOTICE, style="AuthNote.TLabel",
            wraplength=440, justify="left",
        ).pack(anchor="w")

        # Keep the remembered username, never the password.
        remembered = self._state.get_str(KEY_REMEMBERED_USER, "")
        if remembered and self._remember.get():
            self._username.set(remembered)
            self._password_entry.focus_set()

        for box, entry in ((username_box, self._username_entry),
                           (password_box, self._password_entry)):
            entry.bind("<FocusIn>", lambda _e, b=box: b.configure(
                style="AuthFieldFocus.TFrame"))
            entry.bind("<FocusOut>", lambda _e, b=box: b.configure(
                style="AuthField.TFrame"))

    def _field(
        self, parent: tk.Misc, variable: tk.StringVar, *, secret: bool = False
    ) -> tuple[ttk.Entry, ttk.Frame]:
        """A bordered input box whose edge lights up on focus."""
        box = ttk.Frame(parent, style="AuthField.TFrame", padding=(2, 2))
        box.pack(fill="x")
        entry = ttk.Entry(
            box, textvariable=variable, style="Auth.TEntry",
            font=self.fonts.body, show="*" if secret else "",
        )
        entry.pack(side="left", fill="x", expand=True, padx=(10, 4), pady=4)
        return entry, box

    def _toggle_reveal(self) -> None:
        """Show or hide the typed password."""
        hidden = bool(self._password_entry.cget("show"))
        self._password_entry.configure(show="" if hidden else "*")
        self._reveal.configure(text="hide" if hidden else "show")

    def _on_key(self, event: tk.Event) -> None:
        """Warn about Caps Lock, which is the usual cause of a failed sign-in."""
        try:
            caps_on = bool(event.state & 0x0002)
        except TypeError:  # pragma: no cover - exotic event
            return
        self._caps_label.configure(
            text="Caps Lock is on." if caps_on else "",
            foreground=PALETTE.medium if caps_on else PALETTE.text_dim,
        )

    def _centre(self) -> None:
        """Centre the window on screen."""
        self.update_idletasks()
        width, height = 1000, 660
        screen_w, screen_h = self.winfo_screenwidth(), self.winfo_screenheight()
        # Never open larger than the display it is opening on.
        width = min(width, max(720, screen_w - 80))
        height = min(height, max(560, screen_h - 80))
        x = (screen_w - width) // 2
        y = (screen_h - height) // 3
        self.geometry(f"{width}x{height}+{max(0, x)}+{max(0, y)}")

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------
    def _set_subsystem(self, key: str, text: str, colour: str) -> None:
        """Update one row of the live subsystem readout."""
        label = self._subsystem_rows.get(key)
        dot = self._subsystem_dots.get(key)
        if label is None or dot is None:  # pragma: no cover - key typo
            return
        label.configure(text=text, foreground=colour)
        dot.delete("all")
        dot.create_oval(1, 1, 7, 7, fill=colour, outline="")

    def _show_startup_state(self) -> None:
        """Report the true startup state before any sign-in attempt.

        Nothing here is optimistic: each row shows what the probe actually
        returned, and sign-in is disabled outright when the database is not
        reachable rather than letting an operator discover that by failing.
        """
        report: StartupReport = self.context.startup

        if report.database_connected:
            self._set_subsystem("database", "connected", PALETTE.ok)
        else:
            self._set_subsystem("database", "offline", PALETTE.critical)

        if report.schema_ok:
            self._set_subsystem("schema", report.schema_detail, PALETTE.ok)
        else:
            self._set_subsystem(
                "schema", report.schema_detail or "not verified", PALETTE.critical
            )

        blockers: list[str] = []
        if not (report.database_connected and report.schema_ok):
            blockers.append(
                "The database is not available, so sign-in is not possible."
            )
            blockers.extend(report.errors[:2])
        elif not report.admin_exists:
            blockers.append(
                "No administrator account exists yet. Create one with:  "
                "python scripts/create_admin.py"
            )

        if blockers:
            self._show_message("\n".join(blockers), PALETTE.critical)
            self._submit.state(["disabled"])
        elif report.warnings:
            self._show_message(report.warnings[0], PALETTE.medium)

    def _show_message(self, text: str, colour: str = "") -> None:
        """Show the message band, or hide it when there is nothing to say."""
        if not text:
            self._message_frame.pack_forget()
            return
        self._message.configure(text=text, foreground=colour or PALETTE.critical)
        if not self._message_frame.winfo_ismapped():
            self._message_frame.pack(fill="x", pady=(18, 0))

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------
    def _submit_login(self) -> None:
        """Validate input and authenticate on a worker thread."""
        if self._busy:
            return
        authentication = self.context.authentication
        if authentication is None:
            self._fail("AETHRA-SEC is still starting. Please wait.")
            return

        username = self._username.get().strip()
        password = self._password.get()

        if not username or not password:
            self._fail("Enter your username and password.")
            return

        self._busy = True
        self._submit.state(["disabled"])
        self._submit.configure(text="Signing in…")
        self._show_message("")

        def work() -> object:
            return authentication.login(username, password)

        def done(result: object) -> None:
            self._busy = False
            self._submit.state(["!disabled"])
            self._submit.configure(text="Sign in")
            login_result = result  # type: ignore[assignment]
            session = getattr(login_result, "session", None)
            if session is None:
                self._fail("Invalid username or password.")
                return
            self._password.set("")
            self._remember_username(username)
            self._on_success(session)

        def failed(message: str) -> None:
            self._busy = False
            self._submit.state(["!disabled"])
            self._submit.configure(text="Sign in")
            self._password.set("")
            self._fail(message)
            # A refusal may have been the one that triggered a lock, so the
            # banner is re-derived from the server rather than inferred from
            # the message text.
            self._refresh_lock_state()

        self._run_async(work, done, failed)

    def _run_async(
        self,
        work: Callable[[], object],
        on_success: Callable[[object], None],
        on_error: Callable[[str], None],
    ) -> None:
        """Run authentication off the Tk thread.

        The result is handed back through :mod:`aethra_sec.ui.dispatch` rather
        than ``after()``: a worker thread must never touch Tk, and on Python
        3.14 doing so raises "main thread is not in main loop".
        """
        import threading

        def runner() -> None:
            try:
                result = work()
            except AethraError as exc:
                message = exc.user_message
                dispatch.post(lambda: on_error(message))
            except Exception as exc:  # noqa: BLE001
                LOGGER.exception("Sign-in failed unexpectedly.")
                message = user_facing(exc)
                dispatch.post(lambda: on_error(message))
            else:
                dispatch.post(lambda: on_success(result))

        threading.Thread(target=runner, name="login-worker", daemon=True).start()

    def _open_recovery(self, start_tab: int = 0) -> None:
        """Open the password recovery dialog over the sign-in form.

        The modal grab is handed to the dialog and taken back afterwards, so
        the sign-in window stays usable when the operator closes it.
        """
        from aethra_sec.ui.recovery import PasswordRecoveryDialog

        if self._busy:
            return
        dialog = PasswordRecoveryDialog(
            self, self.context, self.fonts, start_tab=start_tab
        )
        try:
            dialog.grab_set()
            self.wait_window(dialog)
        finally:
            try:
                self.grab_set()
            except tk.TclError:  # pragma: no cover - login window already gone
                return
        if dialog.completed:
            self._message.configure(
                text="Password updated. Sign in with your new password.",
                foreground=PALETTE.ok,
            )
            self._password.set("")
            self._password_entry.focus_set()

    def _fail(self, message: str) -> None:
        """Show a sign-in failure message."""
        self._show_message(message, PALETTE.critical)
        self._password_entry.focus_set()

    # ------------------------------------------------------------------
    # Lockout
    # ------------------------------------------------------------------
    def _refresh_lock_state(self) -> None:
        """Ask the server whether this username is locked, and show it.

        The countdown below is drawn from the remaining seconds the *server*
        reports. It is a courtesy, not the control: :meth:`_submit_login`
        always calls the authentication service, which re-derives the lock
        from recorded attempts and refuses on its own account. Editing this
        clock, closing the window or restarting the application changes
        nothing about what is accepted.
        """
        authentication = getattr(self.context, "authentication", None)
        username = self._username.get().strip()
        if authentication is None or not username:
            self._hide_lock()
            return
        try:
            locked, remaining = authentication.lockout_status(username)
        except Exception:  # noqa: BLE001 - never block the form
            LOGGER.debug("Could not read the lock state.", exc_info=True)
            self._hide_lock()
            return
        if not locked:
            self._hide_lock()
            return
        self._lock_deadline = utcnow() + timedelta(seconds=remaining)
        if not self._lock_frame.winfo_ismapped():
            self._lock_frame.pack(fill="x", pady=(18, 0), before=self._message_frame)
        self._tick_lock_countdown()

    def _tick_lock_countdown(self) -> None:
        """Redraw the countdown once a second while the lock stands."""
        if self._lock_job is not None:
            try:
                self.after_cancel(self._lock_job)
            except tk.TclError:
                pass
            self._lock_job = None
        if self._lock_deadline is None:
            return
        remaining = max(0, int((self._lock_deadline - utcnow()).total_seconds() + 0.999))
        self._lock_countdown.configure(
            text=f"Try again in  {format_remaining(remaining)}"
        )
        self._submit.state(["disabled"] if remaining else ["!disabled"])
        if remaining <= 0:
            # Re-ask the server rather than assuming the lock has gone: it is
            # the only thing that decides.
            self._lock_deadline = None
            self.after(200, self._refresh_lock_state)
            return
        self._lock_job = self.after(1000, self._tick_lock_countdown)

    def _hide_lock(self) -> None:
        """Take the banner down and release the button."""
        self._lock_deadline = None
        if self._lock_job is not None:
            try:
                self.after_cancel(self._lock_job)
            except tk.TclError:
                pass
            self._lock_job = None
        if self._lock_frame.winfo_ismapped():
            self._lock_frame.pack_forget()
        if not self._busy:
            self._submit.state(["!disabled"])

    def _remember_username(self, username: str) -> None:
        """Persist the username when asked, and forget it when not.

        Only the username. A password is never written to disk, and clearing
        the box has to actually clear what was stored, or "remember me" would
        be a one-way door.
        """
        remember = bool(self._remember.get())
        self._state.set(KEY_REMEMBER, remember)
        self._state.set(KEY_REMEMBERED_USER, username if remember else "")
        self._state.save()

    def _quit(self) -> None:
        """Close the login window without signing in.

        Only the login window is destroyed, never the shared root: the caller
        (the desktop loop) owns the root's lifetime, so it can decide whether to
        exit or - after a sign-out - show the login window again.
        """
        self.destroy()


def prepare_root(context: ApplicationContext) -> tuple[tk.Tk, Fonts]:
    """Create the single Tk root and start the shared services on it.

    Called once per process. The same root is reused for the login window and
    the console, and across sign-outs, so switching accounts never restarts the
    interpreter or the database pool.
    """
    root = tk.Tk()
    root.withdraw()
    root.title(APP_FULL_NAME)

    # A callback error must never be able to close the console. Installed on
    # the root before any window is shown, because in a packaged build the
    # default handler writes to a stderr that does not exist and takes the
    # process with it. See aethra_sec.runtime.
    runtime.install(root)
    runtime.apply_window_icon(root)

    # Adopt the stored theme *before* the first paint. Applying it afterwards
    # would show the default for a frame and then swap, which is the flash the
    # login window would make most visible.
    stored = UiState(Path(context.settings.log_dir)).get_str(KEY_THEME)
    set_theme(stored or DEFAULT_THEME)
    fonts = apply_theme(root)

    # Start the worker-to-Tk bridge before any window that runs background work.
    dispatch.ensure(root)
    return root, fonts


def prompt_login(
    root: tk.Tk, context: ApplicationContext, fonts: Fonts
) -> Session | None:
    """Show the login window on an existing root and return the session.

    Returns ``None`` when the operator closed the window without signing in.
    Safe to call again after a console session has signed out: the root is
    reused, so this is what switching accounts runs.
    """
    # Make sure the bridge is live even if a previous console stopped it, and
    # hide any leftover console chrome before the modal login appears.
    dispatch.ensure(root)
    try:
        root.withdraw()
    except tk.TclError:  # pragma: no cover - root already gone
        return None

    holder: dict[str, Session | None] = {"session": None}

    def on_success(session: Session) -> None:
        holder["session"] = session
        window.destroy()

    window = LoginWindow(root, context, fonts, on_success)
    window.grab_set()
    root.wait_window(window)
    return holder["session"]


def run_login(
    context: ApplicationContext,
) -> tuple[tk.Tk, Fonts, Session | None]:
    """Create the root, show the login window, and return all three.

    Retained for callers that want the one-shot flow. The desktop loop uses
    :func:`prepare_root` and :func:`prompt_login` directly so it can re-show the
    login window after a sign-out.
    """
    root, fonts = prepare_root(context)
    session = prompt_login(root, context, fonts)
    return root, fonts, session
