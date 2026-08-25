"""Password recovery dialog shown from the sign-in screen (§6, §62).

Two halves of one workflow:

* **Request review** queues a request for an administrator. It never changes a
  credential, and it answers identically whether or not the account exists, so
  the form cannot be used to discover usernames.
* **Set a new password** redeems the one-time code an administrator issues
  after approving that request.

Like the sign-in form, every call runs on a worker thread and returns through
:mod:`aethra_sec.ui.dispatch`: Argon2 hashing is deliberately slow, and a
worker must never touch Tk.
"""

from __future__ import annotations

import socket
import threading
import tkinter as tk
from tkinter import ttk
from typing import Callable

from aethra_sec.core.application import ApplicationContext
from aethra_sec.core.errors import AethraError
from aethra_sec.ui import dispatch
from aethra_sec.ui.theme import PALETTE, Fonts
from aethra_sec.utils.logging import get_logger

LOGGER = get_logger("ui.recovery")

#: Explains the workflow before the operator fills anything in, so the wait for
#: an administrator is expected rather than surprising.
_REQUEST_INTRO = (
    "AETHRA-SEC never resets a password on its own. Raising a request here "
    "puts it in front of the administrators; one of them confirms who you are "
    "and issues a one-time recovery code. Your password stays exactly as it "
    "is until you use that code on the next tab."
)

_REDEEM_INTRO = (
    "Enter the one-time code an administrator gave you after approving your "
    "request. The code works once, for this account only, and expires shortly "
    "after it is issued."
)


def _host_context() -> str:
    """Workstation name recorded with the request."""
    try:
        return socket.gethostname()[:128]
    except Exception:  # noqa: BLE001
        return ""


class PasswordRecoveryDialog(tk.Toplevel):
    """Raise a reset request, or redeem an approved recovery code."""

    def __init__(
        self,
        master: tk.Misc,
        context: ApplicationContext,
        fonts: Fonts,
        *,
        start_tab: int = 0,
    ) -> None:
        """Create the dialog on top of the sign-in window."""
        super().__init__(master)
        self.context = context
        self.fonts = fonts
        self._busy = False
        self._completed = False

        dispatch.ensure(master.winfo_toplevel())

        self.title("AETHRA-SEC - Password recovery")
        self.configure(background=PALETTE.background)
        self.resizable(False, False)
        self.transient(master.winfo_toplevel())
        self.protocol("WM_DELETE_WINDOW", self.close)

        self._build()
        self._notebook.select(1 if start_tab else 0)
        self._centre()

    @property
    def completed(self) -> bool:
        """True when a new password was successfully set in this dialog."""
        return self._completed

    # ------------------------------------------------------------------
    # Layout
    # ------------------------------------------------------------------
    def _build(self) -> None:
        """Construct both tabs."""
        container = ttk.Frame(self, style="TFrame", padding=18)
        container.pack(fill="both", expand=True)

        ttk.Label(
            container, text="Password recovery", style="Title.TLabel"
        ).pack(anchor="w")
        ttk.Label(
            container,
            text="Administrator-approved recovery. No credential changes without a decision.",
            style="Muted.TLabel", wraplength=520, justify="left",
        ).pack(anchor="w", pady=(2, 12))

        self._notebook = ttk.Notebook(container)
        self._notebook.pack(fill="both", expand=True)

        request_tab = ttk.Frame(self._notebook, style="TFrame", padding=14)
        self._notebook.add(request_tab, text="1. Request review")
        self._build_request_tab(request_tab)

        redeem_tab = ttk.Frame(self._notebook, style="TFrame", padding=14)
        self._notebook.add(redeem_tab, text="2. Set a new password")
        self._build_redeem_tab(redeem_tab)

        ttk.Button(container, text="Close", command=self.close).pack(
            anchor="e", pady=(12, 0)
        )

    def _build_request_tab(self, parent: tk.Misc) -> None:
        """The 'ask an administrator' half."""
        ttk.Label(
            parent, text=_REQUEST_INTRO, style="Muted.TLabel",
            wraplength=500, justify="left",
        ).pack(anchor="w", pady=(0, 12))

        self._request_username = self._add_field(parent, "Username")
        self._request_reason = self._add_field(
            parent, "Why do you need a reset? (optional)",
            help_text="Shown to the administrator who reviews the request.",
        )
        self._request_contact = self._add_field(
            parent, "Contact email (optional)",
            help_text="How the administrator can reach you to hand over the code.",
        )

        self._request_message = ttk.Label(
            parent, text="", style="Muted.TLabel", wraplength=500, justify="left"
        )
        self._request_message.pack(anchor="w", pady=(10, 8))

        self._request_button = ttk.Button(
            parent, text="Send request for review", style="Accent.TButton",
            command=self._submit_request,
        )
        self._request_button.pack(anchor="w")

    def _build_redeem_tab(self, parent: tk.Misc) -> None:
        """The 'I have a code' half."""
        ttk.Label(
            parent, text=_REDEEM_INTRO, style="Muted.TLabel",
            wraplength=500, justify="left",
        ).pack(anchor="w", pady=(0, 12))

        minimum = 12
        if self.context.authentication is not None:
            minimum = self.context.authentication.policy.password_min_length

        self._redeem_username = self._add_field(parent, "Username")
        self._redeem_code = self._add_field(
            parent, "Recovery code",
            help_text="As given to you, for example ABCD-EFGH-JKLM-NPQR.",
        )
        self._redeem_password = self._add_field(
            parent, "New password", secret=True,
            help_text=(
                f"At least {minimum} characters, combining three of: lowercase, "
                "uppercase, digits, symbols."
            ),
        )
        self._redeem_confirm = self._add_field(
            parent, "Confirm new password", secret=True
        )

        self._redeem_message = ttk.Label(
            parent, text="", style="Muted.TLabel", wraplength=500, justify="left"
        )
        self._redeem_message.pack(anchor="w", pady=(10, 8))

        self._redeem_button = ttk.Button(
            parent, text="Set new password", style="Accent.TButton",
            command=self._submit_redeem,
        )
        self._redeem_button.pack(anchor="w")

    def _add_field(
        self,
        parent: tk.Misc,
        label: str,
        *,
        secret: bool = False,
        help_text: str = "",
    ) -> tk.StringVar:
        """Add one labelled entry and return its variable."""
        ttk.Label(parent, text=label, style="Muted.TLabel").pack(anchor="w")
        variable = tk.StringVar()
        entry = ttk.Entry(
            parent, textvariable=variable, width=46, font=self.fonts.body,
            show="*" if secret else "",
        )
        entry.pack(fill="x", pady=(3, 2 if help_text else 10))
        if help_text:
            ttk.Label(
                parent, text=help_text, style="Muted.TLabel",
                foreground=PALETTE.text_dim, wraplength=500, justify="left",
            ).pack(anchor="w", pady=(0, 10))
        return variable

    def _centre(self) -> None:
        """Centre the dialog over the screen."""
        self.update_idletasks()
        width, height = 660, 720
        x = (self.winfo_screenwidth() - width) // 2
        y = (self.winfo_screenheight() - height) // 4
        self.geometry(f"{width}x{height}+{max(0, x)}+{max(0, y)}")

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------
    def _submit_request(self) -> None:
        """Queue a reset request for administrator review."""
        recovery = self.context.recovery
        if recovery is None:
            self._say(self._request_message, "AETHRA-SEC is still starting.", error=True)
            return
        username = self._request_username.get().strip()
        if not username:
            self._say(self._request_message, "Enter your username.", error=True)
            return
        if self._busy:
            return

        reason = self._request_reason.get().strip()
        contact = self._request_contact.get().strip()
        host = _host_context()
        self._set_busy(self._request_button, True)
        self._say(self._request_message, "Sending request...")

        self._run_async(
            lambda: recovery.request_reset(
                username, reason=reason, contact=contact, host_context=host
            ),
            lambda acknowledgement: (
                self._set_busy(self._request_button, False),
                self._say(self._request_message, str(acknowledgement), ok=True),
            ),
            lambda message: (
                self._set_busy(self._request_button, False),
                self._say(self._request_message, message, error=True),
            ),
        )

    def _submit_redeem(self) -> None:
        """Set a new password using an approved recovery code."""
        recovery = self.context.recovery
        if recovery is None:
            self._say(self._redeem_message, "AETHRA-SEC is still starting.", error=True)
            return
        username = self._redeem_username.get().strip()
        code = self._redeem_code.get().strip()
        password = self._redeem_password.get()
        confirm = self._redeem_confirm.get()

        if not username or not code:
            self._say(
                self._redeem_message,
                "Enter your username and the recovery code.", error=True,
            )
            return
        if not password:
            self._say(self._redeem_message, "Enter a new password.", error=True)
            return
        if password != confirm:
            self._say(
                self._redeem_message, "The two passwords do not match.", error=True
            )
            return
        if self._busy:
            return

        host = _host_context()
        self._set_busy(self._redeem_button, True)
        self._say(self._redeem_message, "Setting your new password...")

        self._run_async(
            lambda: recovery.complete_reset(
                username, code, password, host_context=host
            ),
            lambda _result: self._password_set(),
            lambda message: (
                self._set_busy(self._redeem_button, False),
                self._say(self._redeem_message, message, error=True),
            ),
        )

    def _password_set(self) -> None:
        """Report success and clear the entered secrets."""
        self._completed = True
        self._set_busy(self._redeem_button, False)
        self._redeem_password.set("")
        self._redeem_confirm.set("")
        self._redeem_code.set("")
        self._say(
            self._redeem_message,
            "Your password has been set. Close this window and sign in with it. "
            "Any other session of your account has been ended.",
            ok=True,
        )
        self._redeem_button.state(["disabled"])

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _set_busy(self, button: ttk.Button, busy: bool) -> None:
        """Disable a button while its request is in flight."""
        self._busy = busy
        try:
            button.state(["disabled"] if busy else ["!disabled"])
        except tk.TclError:  # pragma: no cover - window closing
            pass

    @staticmethod
    def _say(
        label: ttk.Label, message: str, *, ok: bool = False, error: bool = False
    ) -> None:
        """Show a message in one of the two result labels."""
        colour = PALETTE.critical if error else (PALETTE.ok if ok else PALETTE.text_muted)
        try:
            label.configure(text=message, foreground=colour)
        except tk.TclError:  # pragma: no cover - window closing
            pass

    def _run_async(
        self,
        work: Callable[[], object],
        on_success: Callable[[object], None],
        on_error: Callable[[str], None],
    ) -> None:
        """Run a recovery call off the Tk thread."""

        def runner() -> None:
            try:
                result = work()
            except AethraError as exc:
                message = exc.user_message
                dispatch.post(lambda: on_error(message))
            except Exception as exc:  # noqa: BLE001
                LOGGER.exception("Password recovery call failed unexpectedly.")
                message = f"The request could not be completed: {exc}"
                dispatch.post(lambda: on_error(message))
            else:
                dispatch.post(lambda: on_success(result))

        threading.Thread(target=runner, name="recovery-worker", daemon=True).start()

    def close(self) -> None:
        """Close the dialog, leaving no secret in a Tk variable."""
        for variable in (
            self._redeem_password, self._redeem_confirm, self._redeem_code,
        ):
            variable.set("")
        self.destroy()
