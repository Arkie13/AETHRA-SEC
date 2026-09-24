"""Account, role and audit domain models."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from aethra_sec.core.permissions import PermissionSet


@dataclass
class Role:
    """A role and the permissions it grants."""

    id: int | None
    name: str
    description: str = ""
    permissions: tuple[str, ...] = ()
    created_at: datetime | None = None


@dataclass
class User:
    """A user account.

    The password hash never leaves the security layer: repositories return it
    only to :class:`aethra_sec.security.authentication.AuthenticationService`,
    and it is excluded from every export, report and UI surface.
    """

    id: int | None
    username: str
    full_name: str = ""
    email: str = ""
    role_id: int | None = None
    role_name: str = ""
    is_active: bool = True
    is_locked: bool = False
    failed_login_count: int = 0
    locked_until: datetime | None = None
    last_login_at: datetime | None = None
    last_login_host: str = ""
    password_algorithm: str = ""
    password_changed_at: datetime | None = None
    must_change_password: bool = False
    created_at: datetime | None = None
    updated_at: datetime | None = None
    created_by: int | None = None
    permissions: PermissionSet = field(
        default_factory=lambda: PermissionSet(frozenset())
    )

    @property
    def is_admin(self) -> bool:
        """True when the account holds the ADMIN role."""
        return self.role_name.upper() == "ADMIN"

    @property
    def status_text(self) -> str:
        """Account status shown in the user management table."""
        if not self.is_active:
            return "INACTIVE"
        if self.is_locked:
            return "LOCKED"
        return "ACTIVE"

    @property
    def display_name(self) -> str:
        """Full name when known, otherwise the username."""
        return self.full_name.strip() or self.username


@dataclass
class LoginAttempt:
    """One authentication attempt, successful or not."""

    id: int | None
    username: str
    user_id: int | None
    successful: bool
    reason: str = ""
    host_context: str = ""
    attempted_at: datetime | None = None


@dataclass
class UserSessionRecord:
    """A persisted session row (administrative view of who is signed in)."""

    id: int | None
    user_id: int
    username: str = ""
    token_fingerprint: str = ""
    host_context: str = ""
    created_at: datetime | None = None
    last_activity_at: datetime | None = None
    expires_at: datetime | None = None
    ended_at: datetime | None = None
    end_reason: str = ""

    @property
    def is_active(self) -> bool:
        """True while the session has not ended."""
        return self.ended_at is None


class ResetStatus:
    """Lifecycle of a password-reset request (§6).

    A request only ever moves forward: it is raised at the sign-in screen,
    an administrator approves or rejects it, and an approved request is
    consumed exactly once when the owner sets a new password.
    """

    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    COMPLETED = "COMPLETED"
    EXPIRED = "EXPIRED"

    #: States an administrator can still act on.
    OPEN: tuple[str, ...] = (PENDING, APPROVED)
    #: Every state, for validating a status filter.
    ALL: tuple[str, ...] = (PENDING, APPROVED, REJECTED, COMPLETED, EXPIRED)


@dataclass
class PasswordResetRequest:
    """One password recovery request awaiting or carrying an admin decision.

    The one-time authorisation code issued on approval is **not** part of this
    model: only its SHA-256 digest is stored, and the code itself is shown to
    the approving administrator once and never again.
    """

    id: int | None
    user_id: int
    username: str
    status: str = ResetStatus.PENDING
    reason: str = ""
    contact: str = ""
    host_context: str = ""
    requested_at: datetime | None = None
    expires_at: datetime | None = None
    reviewed_by: int | None = None
    reviewer_username: str = ""
    reviewed_at: datetime | None = None
    review_note: str = ""
    code_expires_at: datetime | None = None
    code_attempts: int = 0
    completed_at: datetime | None = None

    @property
    def is_pending(self) -> bool:
        """True while the request is still waiting for a decision."""
        return self.status == ResetStatus.PENDING

    @property
    def is_approved(self) -> bool:
        """True once an administrator has approved the request."""
        return self.status == ResetStatus.APPROVED

    def has_expired(self, now: datetime) -> bool:
        """True when the request or its approval has timed out.

        A pending request expires at :attr:`expires_at`; an approved one
        expires when its code does, which is deliberately much sooner.
        """
        if self.status == ResetStatus.PENDING:
            return self.expires_at is not None and now >= self.expires_at
        if self.status == ResetStatus.APPROVED:
            return self.code_expires_at is not None and now >= self.code_expires_at
        return False

    @property
    def status_text(self) -> str:
        """Status shown in the administrative queue."""
        return self.status


@dataclass
class AuditRecord:
    """An append-only audit entry with chained integrity hashing (§33, §56)."""

    id: int | None
    occurred_at: datetime | None
    user_id: int | None
    username: str
    action: str
    category: str = "general"
    target_type: str = ""
    target_id: str = ""
    result: str = "SUCCESS"
    detail: str = ""
    host_context: str = ""
    source: str = "SYSTEM"
    previous_hash: str = ""
    record_hash: str = ""

    @property
    def succeeded(self) -> bool:
        """True when the audited action completed successfully."""
        return self.result.upper() == "SUCCESS"
