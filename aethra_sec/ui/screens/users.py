"""User management screen (§70).

Administrator-only. Reachable only when the session holds ``user.manage``, and
every action is re-checked and audited in the service layer regardless of what
the interface allows.

Four things happen here: accounts are registered and maintained, password
recovery requests are reviewed, sign-in history is read, and live sessions are
ended. The password recovery queue is the one place a forgotten credential can
be restored, and it needs an administrator's decision before it does anything.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Any

from aethra_sec.core.permissions import Permission
from aethra_sec.models.user import LoginAttempt, PasswordResetRequest, ResetStatus, User
from aethra_sec.services.recovery_service import Approval
from aethra_sec.services.user_service import CreatedAccount
from aethra_sec.ui.base import Screen
from aethra_sec.ui.theme import PALETTE, configure_text_widget
from aethra_sec.ui.widgets import (
    Card,
    Column,
    DataTable,
    EmptyState,
    FormDialog,
    FormField,
    Toolbar,
    confirm,
    show_message,
)
from aethra_sec.utils.timeutil import format_local

USER_COLUMNS = (
    # The real users.id primary key, not a row number: an administrator
    # reading an audit entry or a support request needs the identifier the
    # rest of the system uses, and until now the screen never showed it.
    Column("id", "ID", width=56, anchor="e"),
    Column("username", "Username", width=140),
    Column("full_name", "Full name", width=180),
    Column("email", "Email", width=210),
    Column("role", "Role", width=90),
    Column("status", "Status", width=90, colour_by="status"),
    Column("failures", "Failed logins", width=100, anchor="e"),
    Column("last_login", "Last sign-in", width=155),
    Column("last_host", "Last host", width=140),
    Column("created", "Created", width=145),
    # When an administrator last edited the account. Read from the stored
    # column and never computed here: an account nobody has edited shows a
    # dash, because repeating the created date would assert an edit that
    # never took place.
    Column("date_modified", "Date Modified", width=145),
)

ATTEMPT_COLUMNS = (
    Column("time", "Time", width=160),
    Column("username", "Username", width=140),
    Column("result", "Result", width=90, colour_by="state"),
    Column("reason", "Reason", width=180),
    Column("host", "Host", width=170),
)

SESSION_COLUMNS = (
    Column("username", "Username", width=140),
    Column("host", "Host", width=170),
    Column("created", "Signed in", width=160),
    Column("activity", "Last activity", width=160),
    Column("expires", "Expires", width=160),
)

#: Ordered so the fields a decision turns on - who, what state, how long left -
#: are readable without scrolling.
RESET_COLUMNS = (
    Column("requested", "Requested", width=145),
    Column("username", "Account", width=110),
    Column("status", "Status", width=95, colour_by="status"),
    Column("deadline", "Deadline", width=145),
    Column("attempts", "Code tries", width=85, anchor="e"),
    Column("reason", "Stated reason", width=230),
    Column("contact", "Contact", width=160),
    Column("host", "From host", width=120),
    Column("reviewer", "Decided by", width=110),
    Column("reviewed", "Decided", width=145),
)

#: Queue filters offered above the recovery table.
RESET_FILTERS: tuple[tuple[str, str], ...] = (
    ("Awaiting review", ResetStatus.PENDING),
    ("Approved (code live)", ResetStatus.APPROVED),
    ("Rejected", ResetStatus.REJECTED),
    ("Completed", ResetStatus.COMPLETED),
    ("Expired", ResetStatus.EXPIRED),
    ("All requests", ""),
)


class UsersScreen(Screen):
    """Create, edit and control accounts."""

    title = "User Management"
    subtitle = (
        "Registration, password recovery, roles, sign-in history and active "
        "sessions (administrator only)"
    )
    required_permission = "user.manage"

    def __init__(self, parent: tk.Misc, app: Any) -> None:
        """Create the screen."""
        super().__init__(parent, app)
        self._users: dict[int, User] = {}
        self._roles: list[str] = ["ADMIN", "USER"]
        self._resets: dict[int, PasswordResetRequest] = {}
        self._pending_resets = 0
        self._resets_table: DataTable | None = None

    # ------------------------------------------------------------------
    # Layout
    # ------------------------------------------------------------------
    def build(self) -> None:
        """Construct the user management screen."""
        summary = Card(self, "Accounts", fonts=self.fonts, padding=12)
        summary.pack(fill="x")
        self._summary_label = ttk.Label(summary, text="", style="CardMuted.TLabel")
        self._summary_label.pack(anchor="w")
        self._reset_summary_label = ttk.Label(
            summary, text="", style="CardMuted.TLabel", wraplength=900, justify="left"
        )
        self._reset_summary_label.pack(anchor="w", pady=(4, 0))

        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True, pady=(10, 0))
        self._notebook = notebook

        accounts = ttk.Frame(notebook, style="TFrame", padding=10)
        notebook.add(accounts, text="Accounts")
        self._build_accounts(accounts)

        resets = ttk.Frame(notebook, style="TFrame", padding=10)
        notebook.add(resets, text="Password recovery")
        self._build_resets(resets)

        history = ttk.Frame(notebook, style="TFrame", padding=10)
        notebook.add(history, text="Sign-in history")
        self._build_history(history)

        sessions = ttk.Frame(notebook, style="TFrame", padding=10)
        notebook.add(sessions, text="Active sessions")
        self._build_sessions(sessions)

        roles = ttk.Frame(notebook, style="TFrame", padding=10)
        notebook.add(roles, text="Roles & permissions")
        self._build_roles(roles)

    def _build_accounts(self, parent: tk.Misc) -> None:
        """Account table and its controls."""
        card = Card(parent, "User accounts", fonts=self.fonts, padding=12)
        card.pack(fill="both", expand=True)

        toolbar = Toolbar(card)
        toolbar.pack(fill="x", pady=(0, 6))
        toolbar.add_button("Create account", self._create_user, style="Accent.TButton")
        toolbar.add_button("Edit", self._edit_user)
        toolbar.add_button("Reset password", self._reset_password)
        toolbar.add_button("Unlock", self._unlock)
        toolbar.add_button("Deactivate", lambda: self._set_active(False))
        toolbar.add_button("Activate", lambda: self._set_active(True))
        toolbar.add_button("Force sign-out", self._force_logout)
        toolbar.add_button("Refresh", self.refresh)

        self._table = DataTable(card, USER_COLUMNS, height=12)
        self._table.pack(fill="both", expand=True)

    def _build_resets(self, parent: tk.Misc) -> None:
        """The password recovery queue and its decisions."""
        card = Card(
            parent, "Password recovery requests",
            subtitle="raised at the sign-in screen; nothing changes until you decide",
            fonts=self.fonts, padding=12,
        )
        card.pack(fill="both", expand=True)

        if not self.can(Permission.USER_RESET_APPROVE):
            # The screen already requires user.manage, but approving recovery
            # is a separate grant and the service enforces it independently.
            EmptyState(
                card,
                "You cannot review password recovery requests",
                detail=(
                    "Reviewing and approving password recovery needs the "
                    "'user.reset_approve' permission. Ask an administrator who "
                    "holds it to work the queue."
                ),
                icon="🔒",
            ).pack(fill="both", expand=True)
            self._resets_table = None
            return

        toolbar = Toolbar(card)
        toolbar.pack(fill="x", pady=(0, 6))
        toolbar.add_button("Approve and issue code", self._approve_reset,
                           style="Accent.TButton")
        toolbar.add_button("Reject", self._reject_reset)
        toolbar.add_button("Refresh", self._load_resets)
        toolbar.add_separator()
        toolbar.add_label("Show")
        self._reset_filter = tk.StringVar(value=RESET_FILTERS[0][0])
        filter_box = ttk.Combobox(
            toolbar, textvariable=self._reset_filter, state="readonly", width=20,
            values=[label for label, _status in RESET_FILTERS],
        )
        filter_box.pack(side="left", padx=(0, 6))
        filter_box.bind("<<ComboboxSelected>>", lambda _event: self._load_resets())

        ttk.Label(
            card,
            text=(
                "Approving issues a one-time code that is shown to you once. "
                "Hand it to the account owner through a channel you trust - "
                "they redeem it from the sign-in screen under "
                "'I have a recovery code'. The code expires quickly and works "
                "once; AETHRA-SEC never emails it and never stores it."
            ),
            style="CardDim.TLabel", wraplength=900, justify="left",
        ).pack(anchor="w", pady=(0, 6))

        self._resets_table = DataTable(card, RESET_COLUMNS, height=12)
        self._resets_table.pack(fill="both", expand=True)

    def _build_history(self, parent: tk.Misc) -> None:
        """Sign-in attempt history."""
        card = Card(
            parent, "Sign-in attempts", subtitle="successful and failed",
            fonts=self.fonts, padding=12,
        )
        card.pack(fill="both", expand=True)
        toolbar = Toolbar(card)
        toolbar.pack(fill="x", pady=(0, 6))
        toolbar.add_button("Refresh", self._load_history)
        self._attempts_table = DataTable(card, ATTEMPT_COLUMNS, height=14)
        self._attempts_table.pack(fill="both", expand=True)

    def _build_sessions(self, parent: tk.Misc) -> None:
        """Currently signed-in sessions."""
        card = Card(parent, "Active sessions", fonts=self.fonts, padding=12)
        card.pack(fill="both", expand=True)
        toolbar = Toolbar(card)
        toolbar.pack(fill="x", pady=(0, 6))
        toolbar.add_button("Refresh", self._load_sessions)
        self._sessions_table = DataTable(card, SESSION_COLUMNS, height=14)
        self._sessions_table.pack(fill="both", expand=True)

    def _build_roles(self, parent: tk.Misc) -> None:
        """Role and permission reference."""
        card = Card(parent, "Roles and permissions", fonts=self.fonts, padding=12)
        card.pack(fill="both", expand=True)
        self._roles_text = tk.Text(card, wrap="word")
        configure_text_widget(self._roles_text, self.fonts)
        scrollbar = ttk.Scrollbar(card, orient="vertical", command=self._roles_text.yview)
        self._roles_text.configure(yscrollcommand=scrollbar.set, state="disabled")
        self._roles_text.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

    # ------------------------------------------------------------------
    # Data
    # ------------------------------------------------------------------
    def on_show(self) -> None:
        """Load every tab."""
        self.refresh()
        self._load_resets()
        self._load_history()
        self._load_sessions()
        self._load_roles()

    def refresh(self) -> None:
        """Reload the account list."""
        users = self.context.users
        session = self.session
        if users is None or session is None:
            return
        self.run_async(
            lambda: (users.list_users(session), users.statistics(session)),
            self._apply,
            name="users-load",
        )

    def _apply(self, payload: tuple[list[User], dict[str, Any]]) -> None:
        """Render the account table."""
        user_list, statistics = payload
        self._users = {u.id: u for u in user_list if u.id is not None}
        self._table.set_rows(
            [
                {
                    "_id": user.id,
                    "id": user.id,
                    "username": user.username,
                    "full_name": user.full_name or "-",
                    "email": user.email or "-",
                    "role": user.role_name or "-",
                    "status": user.status_text,
                    "failures": user.failed_login_count,
                    "last_login": format_local(user.last_login_at),
                    "last_host": user.last_login_host or "-",
                    "created": format_local(user.created_at, "%d %b %Y"),
                    # The stored value, or a dash. format_local already
                    # renders None as a dash, so a never-edited account is
                    # not given a date it never earned.
                    "date_modified": format_local(user.date_modified),
                }
                for user in user_list
            ]
        )
        self._summary_label.configure(
            text=(
                f"{statistics.get('total', 0)} account(s) · "
                f"{statistics.get('active', 0)} active · "
                f"{statistics.get('administrators', 0)} administrator(s) · "
                f"{statistics.get('active_sessions', 0)} active session(s). "
                "The last active administrator cannot be deactivated or demoted."
            )
        )
        self.status(f"{len(user_list)} account(s) loaded.")

    def _selected(self) -> User | None:
        """The currently selected account."""
        row = self._table.selected_row()
        if row is None:
            return None
        return self._users.get(int(row.get("_id") or 0))

    def _load_resets(self) -> None:
        """Reload the password recovery queue."""
        recovery = self.context.recovery
        session = self.session
        if recovery is None or session is None or self._resets_table is None:
            return
        status = dict(RESET_FILTERS).get(self._reset_filter.get(), "")
        self.run_async(
            lambda: (
                recovery.list_requests(session, status=status, limit=300),
                recovery.pending_count(session),
            ),
            self._apply_resets,
            name="reset-queue",
        )

    def _apply_resets(self, payload: tuple[list[PasswordResetRequest], int]) -> None:
        """Render the recovery queue and the pending counter."""
        requests, pending = payload
        if self._resets_table is None:
            return
        self._resets = {r.id: r for r in requests if r.id is not None}
        self._pending_resets = pending
        self._resets_table.set_rows(
            [
                {
                    "_id": request.id,
                    "requested": format_local(request.requested_at),
                    "username": request.username,
                    "status": request.status,
                    "reason": request.reason or "(none given)",
                    "contact": request.contact or "-",
                    "host": request.host_context or "-",
                    "reviewer": request.reviewer_username or "-",
                    "reviewed": format_local(request.reviewed_at),
                    "deadline": format_local(
                        request.code_expires_at
                        if request.is_approved
                        else request.expires_at
                    ),
                    "attempts": request.code_attempts,
                }
                for request in requests
            ]
        )
        if pending:
            self._reset_summary_label.configure(
                text=(
                    f"{pending} password recovery request(s) awaiting review. "
                    "Open the Password recovery tab to decide on them - the "
                    "accounts cannot change their own password until you do."
                ),
                foreground=PALETTE.medium,
            )
        else:
            self._reset_summary_label.configure(
                text="No password recovery requests are awaiting review.",
                foreground=PALETTE.text_muted,
            )
        self.status(f"{len(requests)} recovery request(s) listed.")

    def _selected_reset(self) -> PasswordResetRequest | None:
        """The currently selected recovery request."""
        if self._resets_table is None:
            return None
        row = self._resets_table.selected_row()
        if row is None:
            return None
        return self._resets.get(int(row.get("_id") or 0))

    def _approve_reset(self) -> None:
        """Approve the selected request and show its one-time code."""
        request = self._selected_reset()
        recovery = self.context.recovery
        session = self.session
        if request is None or request.id is None or recovery is None or session is None:
            self.status("Select a request first.")
            return
        if not request.is_pending:
            self.status(
                f"Request #{request.id} is already {request.status.lower()}."
            )
            return
        minutes = recovery.policy.code_ttl_minutes
        if not confirm(
            self, "Approve password recovery",
            f"Approve the recovery request for '{request.username}'?",
            detail=(
                "Approve only after you have confirmed, off-system, that the "
                "person asking really is the owner of this account.\n\n"
                f"A one-time code will be shown to you once and stays usable "
                f"for {minutes} minute(s). It replaces no password by itself - "
                "the owner sets their own new password with it."
            ),
            confirm_label="Approve and issue code",
        ):
            return
        note = FormDialog(
            self, "Approval note",
            [
                FormField(
                    "note", "How was identity confirmed?",
                    help_text=(
                        "Recorded in the audit trail with your name, for "
                        "example 'confirmed in person' or 'verified by phone'."
                    ),
                ),
            ],
            fonts=self.fonts, submit_label="Approve",
            intro="Optional, but it is what makes the decision reviewable later.",
        ).show()
        if note is None:
            return
        request_id = request.id
        self.run_async(
            lambda: recovery.approve(session, request_id, note=note.get("note", "")),
            self._show_approval,
            name="reset-approve",
        )

    def _show_approval(self, approval: Approval) -> None:
        """Show the issued code once, then refresh the queue."""
        show_message(
            self, "Recovery code issued",
            f"One-time recovery code for '{approval.username}'",
            detail=(
                f"{approval.code}\n\n"
                f"Valid until {format_local(approval.expires_at)}, for this "
                "account only, and usable once.\n\n"
                "Give it to the account owner through a channel you trust. It "
                "is shown here once and is not stored anywhere in readable "
                "form - if it is lost, reject the request and let the owner "
                "raise a new one.\n\n"
                "The owner redeems it from the sign-in screen under "
                "'I have a recovery code'."
            ),
            fonts=self.fonts, mono=True,
        )
        self._load_resets()

    def _reject_reset(self) -> None:
        """Reject the selected request."""
        request = self._selected_reset()
        recovery = self.context.recovery
        session = self.session
        if request is None or request.id is None or recovery is None or session is None:
            self.status("Select a request first.")
            return
        if request.status not in ResetStatus.OPEN:
            self.status(
                f"Request #{request.id} is already {request.status.lower()}."
            )
            return
        values = FormDialog(
            self, f"Reject recovery for {request.username}",
            [
                FormField(
                    "note", "Reason for rejecting",
                    help_text="Recorded in the audit trail with your name.",
                ),
            ],
            fonts=self.fonts, submit_label="Reject request",
            intro=(
                "The account keeps its current password and any code already "
                "issued for this request stops working immediately."
            ),
        ).show()
        if values is None:
            return
        request_id = request.id
        self.run_async(
            lambda: recovery.reject(session, request_id, note=values.get("note", "")),
            lambda _r: (
                self.status(f"Request #{request_id} rejected."),
                self._load_resets(),
            ),
            name="reset-reject",
        )

    def _load_history(self) -> None:
        """Reload sign-in attempts."""
        users = self.context.users
        session = self.session
        if users is None or session is None:
            return
        self.run_async(
            lambda: users.login_history(session, limit=300),
            self._apply_history,
            name="login-history",
        )

    def _apply_history(self, attempts: list[LoginAttempt]) -> None:
        """Render the sign-in attempt table."""
        self._attempts_table.set_rows(
            [
                {
                    "time": format_local(attempt.attempted_at),
                    "username": attempt.username,
                    "result": "PASS" if attempt.successful else "FAIL",
                    "reason": attempt.reason or ("password" if attempt.successful else "-"),
                    "host": attempt.host_context or "-",
                }
                for attempt in attempts
            ]
        )

    def _load_sessions(self) -> None:
        """Reload active sessions."""
        users = self.context.users
        session = self.session
        if users is None or session is None:
            return
        self.run_async(
            lambda: users.active_sessions(session), self._apply_sessions,
            name="sessions-load",
        )

    def _apply_sessions(self, records: list[Any]) -> None:
        """Render the active session table."""
        self._sessions_table.set_rows(
            [
                {
                    "username": record.username or "-",
                    "host": record.host_context or "-",
                    "created": format_local(record.created_at),
                    "activity": format_local(record.last_activity_at),
                    "expires": format_local(record.expires_at),
                }
                for record in records
            ]
        )

    def _load_roles(self) -> None:
        """Reload the role/permission reference."""
        users = self.context.users
        session = self.session
        if users is None or session is None:
            return
        self.run_async(lambda: users.roles(session), self._apply_roles, name="roles-load")

    def _apply_roles(self, roles: list[Any]) -> None:
        """Render the role/permission reference."""
        self._roles = [role.name for role in roles] or ["ADMIN", "USER"]
        lines = [
            "Permissions are enforced in the service layer. Hiding a control in "
            "the interface is a convenience; the backend refuses the action "
            "regardless of what the interface allows.",
            "",
        ]
        for role in roles:
            lines.append(f"{role.name}  ({len(role.permissions)} permission(s))")
            lines.append(f"  {role.description}")
            for permission in role.permissions:
                lines.append(f"    - {permission}")
            lines.append("")
        self._roles_text.configure(state="normal")
        self._roles_text.delete("1.0", "end")
        self._roles_text.insert("1.0", "\n".join(lines))
        self._roles_text.configure(state="disabled")

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------
    def _create_user(self) -> None:
        """Create a new account."""
        users = self.context.users
        session = self.session
        if users is None or session is None:
            return
        minimum = (
            self.context.authentication.policy.password_min_length
            if self.context.authentication
            else 12
        )
        values = FormDialog(
            self, "Register a new account",
            [
                FormField("username", "Username", required=True,
                          help_text="3-32 characters: letters, digits, dots, underscores, hyphens."),
                FormField("full_name", "Full name",
                          help_text="Shown throughout the console instead of the username."),
                FormField("email", "Email",
                          help_text=(
                              "Used to reach the operator, and required if email "
                              "two-factor is enabled."
                          )),
                FormField("role_name", "Role", kind="choice", value="USER",
                          options=self._roles, required=True,
                          help_text=(
                              "ADMIN can manage accounts, settings, the audit trail "
                              "and password recovery. USER monitors, assesses, "
                              "reviews alerts and reads reports."
                          )),
                FormField("password", "Initial password", kind="password",
                          help_text=(
                              f"At least {minimum} characters, combining three of: "
                              "lowercase, uppercase, digits, symbols. Leave blank "
                              "to generate a strong one."
                          )),
                FormField("must_change_password", "Require change at next sign-in",
                          kind="bool", value=True),
            ],
            fonts=self.fonts, submit_label="Create account",
            intro=(
                "The account is created immediately, becomes active at once, and "
                "the registration is written to the audit trail with your name. "
                "A duplicate username is refused."
            ),
        ).show()
        if not values:
            return
        self.run_async(
            lambda: users.create_user(
                session,
                username=values["username"],
                password=values["password"],
                role_name=values["role_name"],
                full_name=values["full_name"],
                email=values["email"],
                must_change_password=bool(values["must_change_password"]),
            ),
            self._show_created_account,
            name="user-create",
        )

    def _show_created_account(self, account: CreatedAccount) -> None:
        """Show the new account's credentials once, then reload the table."""
        change_note = (
            "They must change it at first sign-in."
            if account.must_change_password
            else "They are not required to change it at first sign-in."
        )
        show_message(
            self, "Account registered",
            f"'{account.username}' created with role {account.role_name}",
            detail=(
                f"Username: {account.username}\n"
                f"Password: {account.password}\n\n"
                + (
                    "This password was generated for you. "
                    if account.generated
                    else ""
                )
                + "It is shown once and is not stored in plaintext anywhere. "
                "Give it to the operator through a secure channel. "
                + change_note
            ),
            fonts=self.fonts, mono=True,
        )
        self.status(f"Account '{account.username}' registered.")
        self.refresh()

    def _edit_user(self) -> None:
        """Edit the selected account."""
        user = self._selected()
        users = self.context.users
        session = self.session
        if user is None or user.id is None or users is None or session is None:
            self.status("Select an account first.")
            return
        values = FormDialog(
            self, f"Edit {user.username}",
            [
                FormField("full_name", "Full name", value=user.full_name),
                FormField("email", "Email", value=user.email),
                FormField("role_name", "Role", kind="choice",
                          value=user.role_name or "USER", options=self._roles,
                          required=True),
                FormField("is_active", "Active", kind="bool", value=user.is_active),
            ],
            fonts=self.fonts, submit_label="Save",
        ).show()
        if not values:
            return
        user_id = user.id
        self.run_async(
            lambda: users.update_user(
                session, user_id,
                full_name=values["full_name"],
                email=values["email"],
                role_name=values["role_name"],
                is_active=bool(values["is_active"]),
            ),
            lambda _r: (self.status("Account updated."), self.refresh()),
            name="user-update",
        )

    def _reset_password(self) -> None:
        """Reset the selected account's password."""
        user = self._selected()
        users = self.context.users
        session = self.session
        if user is None or user.id is None or users is None or session is None:
            self.status("Select an account first.")
            return
        if not confirm(
            self, "Reset password", f"Reset the password for '{user.username}'?",
            detail=(
                "A new password is generated and shown once. Every session of "
                "this account is terminated, and the account must change the "
                "password at next sign-in."
            ),
            confirm_label="Reset password", danger=True,
        ):
            return
        user_id = user.id
        self.run_async(
            lambda: users.reset_password(session, user_id),
            lambda password: show_message(
                self, "Password reset",
                f"New password for '{user.username}'",
                detail=(
                    f"{password}\n\n"
                    "This password is shown once and is not stored in plaintext "
                    "anywhere. Give it to the user through a secure channel; "
                    "they must change it at next sign-in."
                ),
                fonts=self.fonts, mono=True,
            ),
            name="user-reset",
        )

    def _unlock(self) -> None:
        """Clear an automatic lockout."""
        user = self._selected()
        users = self.context.users
        session = self.session
        if user is None or user.id is None or users is None or session is None:
            self.status("Select an account first.")
            return
        user_id = user.id
        self.run_async(
            lambda: users.unlock(session, user_id),
            lambda _r: (self.status(f"'{user.username}' unlocked."), self.refresh()),
            name="user-unlock",
        )

    def _set_active(self, active: bool) -> None:
        """Activate or deactivate the selected account."""
        user = self._selected()
        users = self.context.users
        session = self.session
        if user is None or user.id is None or users is None or session is None:
            self.status("Select an account first.")
            return
        if not active and not confirm(
            self, "Deactivate account", f"Deactivate '{user.username}'?",
            detail=(
                "The account can no longer sign in and its sessions are "
                "terminated. Its historical records and audit trail are kept."
            ),
            confirm_label="Deactivate", danger=True,
        ):
            return
        user_id = user.id
        self.run_async(
            lambda: users.set_active(session, user_id, active),
            lambda _r: (
                self.status(f"'{user.username}' {'activated' if active else 'deactivated'}."),
                self.refresh(),
            ),
            name="user-active",
        )

    def _force_logout(self) -> None:
        """Terminate every session of the selected account."""
        user = self._selected()
        users = self.context.users
        session = self.session
        if user is None or user.id is None or users is None or session is None:
            self.status("Select an account first.")
            return
        user_id = user.id
        self.run_async(
            lambda: users.force_logout(session, user_id),
            lambda count: (
                self.status(f"Terminated {count} session(s) for '{user.username}'."),
                self._load_sessions(),
            ),
            name="user-logout",
        )
