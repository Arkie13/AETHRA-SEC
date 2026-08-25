"""Authentication service (§6).

Guarantees:

* passwords are verified against a stored hash - never compared as text;
* failure messages are identical for an unknown username and a wrong password,
  so account existence is not disclosed (§62);
* consecutive failures lock the account for a configurable period;
* every attempt, success and failure alike, is recorded in ``login_attempts``
  and in the hash-chained audit trail;
* sessions are persisted so an administrator can see and terminate them.
"""

from __future__ import annotations

import socket
from dataclasses import dataclass
from datetime import timedelta

from aethra_sec.core.errors import (
    AccountInactiveError,
    AccountLockedError,
    AuthenticationError,
    ValidationFailedError,
)
from aethra_sec.core.permissions import PermissionSet
from aethra_sec.core.session import Session, SessionManager
from aethra_sec.database.repositories.users import UserRepository
from aethra_sec.models.user import User
from aethra_sec.security.audit import AuditAction, AuditCategory, AuditService
from aethra_sec.security.otp import OtpService
from aethra_sec.security.password import PasswordHashService, token_fingerprint
from aethra_sec.utils.logging import get_logger
from aethra_sec.utils.timeutil import utcnow
from aethra_sec.utils.validation import ValidationError, validate_password

LOGGER = get_logger("security.authentication")

#: Presented for every failed sign-in regardless of the underlying reason.
GENERIC_FAILURE_MESSAGE = "Invalid username or password."


@dataclass
class AuthenticationPolicy:
    """Tunable authentication limits, loaded from ``system_settings``."""

    max_failed_logins: int = 5
    lockout_minutes: int = 15
    session_timeout_minutes: int = 60
    password_min_length: int = 12


@dataclass
class LoginResult:
    """Outcome of a sign-in attempt.

    A result with ``session is None`` and ``otp_required`` true means the
    password was correct and a second factor must now be supplied.
    """

    session: Session | None = None
    otp_required: bool = False
    otp_user_id: int | None = None
    otp_delivery_error: str = ""
    must_change_password: bool = False

    @property
    def authenticated(self) -> bool:
        """True when a usable session was issued."""
        return self.session is not None


class AuthenticationService:
    """Verifies credentials and issues sessions."""

    def __init__(
        self,
        users: UserRepository,
        sessions: SessionManager,
        passwords: PasswordHashService,
        audit: AuditService,
        otp: OtpService | None = None,
        policy: AuthenticationPolicy | None = None,
    ) -> None:
        """Wire the service to its collaborators."""
        self._users = users
        self._sessions = sessions
        self._passwords = passwords
        self._audit = audit
        self._otp = otp
        self._policy = policy or AuthenticationPolicy()
        self._sessions.set_timeout(self._policy.session_timeout_minutes)

    @property
    def policy(self) -> AuthenticationPolicy:
        """The active authentication policy."""
        return self._policy

    def apply_policy(self, policy: AuthenticationPolicy) -> None:
        """Replace the policy (called when an administrator edits settings)."""
        self._policy = policy
        self._sessions.set_timeout(policy.session_timeout_minutes)

    @staticmethod
    def _host_context() -> str:
        """Workstation name recorded with attempts and sessions."""
        try:
            return socket.gethostname()[:128]
        except Exception:  # noqa: BLE001
            return ""

    # ------------------------------------------------------------------
    # Sign in
    # ------------------------------------------------------------------
    def login(self, username: str, password: str) -> LoginResult:
        """Authenticate a user.

        Raises:
            AuthenticationError: on any credential failure. The message is
                deliberately identical for unknown users and wrong passwords.
            AccountLockedError / AccountInactiveError: when the account exists
                but cannot be used; these are distinguishable because the
                operator needs to know to contact an administrator, and they
                are only reachable *after* the password verified or after the
                lockout has already been triggered by this same account.
        """
        host = self._host_context()
        candidate = (username or "").strip()

        if not candidate or not password:
            self._record_failure(candidate, None, "empty_credentials", host)
            raise AuthenticationError(user_message=GENERIC_FAILURE_MESSAGE)

        user = self._users.get_by_username(candidate)
        if user is None or user.id is None:
            # Unknown account: record the attempt, answer with the generic
            # message, and do not reveal that the username does not exist.
            self._record_failure(candidate, None, "unknown_user", host)
            raise AuthenticationError(user_message=GENERIC_FAILURE_MESSAGE)

        if self._is_locked(user):
            self._record_failure(candidate, user.id, "account_locked", host)
            self._audit.record(
                AuditAction.LOGIN_LOCKED,
                user_id=user.id,
                username=user.username,
                category=AuditCategory.AUTHENTICATION,
                result="DENIED",
                detail="Sign-in refused: the account is locked.",
            )
            raise AccountLockedError()

        stored_hash, _algorithm = self._users.get_password_hash(user.id)
        if not self._passwords.verify(password, stored_hash):
            failures = self._users.register_failed_login(user.id)
            reason = "bad_password"
            if failures >= self._policy.max_failed_logins:
                self._users.set_locked(
                    user.id,
                    True,
                    utcnow() + timedelta(minutes=self._policy.lockout_minutes),
                )
                reason = "bad_password_locked"
                self._audit.record(
                    AuditAction.LOGIN_LOCKED,
                    user_id=user.id,
                    username=user.username,
                    category=AuditCategory.AUTHENTICATION,
                    result="DENIED",
                    detail=(
                        f"Account locked after {failures} consecutive failed "
                        f"sign-in attempts; lockout lasts "
                        f"{self._policy.lockout_minutes} minute(s)."
                    ),
                )
            self._record_failure(candidate, user.id, reason, host)
            raise AuthenticationError(user_message=GENERIC_FAILURE_MESSAGE)

        if not user.is_active:
            self._record_failure(candidate, user.id, "account_inactive", host)
            raise AccountInactiveError()

        # Upgrade a credential that was hashed with weaker parameters.
        if self._passwords.needs_rehash(stored_hash):
            try:
                upgraded = self._passwords.hash(password)
                self._users.set_password(
                    user.id, upgraded.hash, upgraded.algorithm,
                    must_change=user.must_change_password,
                )
                LOGGER.info("Upgraded a stored credential to %s.", upgraded.algorithm)
            except Exception:  # noqa: BLE001 - never block a valid sign-in
                LOGGER.exception("Credential upgrade failed; sign-in continues.")

        if self._otp and self._otp.required_for(user.email):
            challenge = self._otp.issue(user.id, user.email)
            return LoginResult(
                otp_required=True,
                otp_user_id=user.id,
                otp_delivery_error=challenge.delivery_error,
                must_change_password=user.must_change_password,
            )

        session = self._establish_session(user, host)
        return LoginResult(
            session=session, must_change_password=user.must_change_password
        )

    def complete_otp(self, user_id: int, code: str) -> LoginResult:
        """Finish a sign-in that required a second factor.

        Raises:
            AuthenticationError: when the code is wrong or expired.
        """
        if not self._otp:
            raise AuthenticationError(
                user_message="Two-factor authentication is not configured."
            )
        ok, reason = self._otp.verify(user_id, code)
        if not ok:
            self._audit.record(
                AuditAction.LOGIN_FAILED,
                user_id=user_id,
                category=AuditCategory.AUTHENTICATION,
                result="FAILURE",
                detail=f"Second factor rejected: {reason}",
            )
            raise AuthenticationError(user_message=reason)

        user = self._users.get_by_id(user_id)
        if user is None or user.id is None or not user.is_active:
            raise AuthenticationError(user_message=GENERIC_FAILURE_MESSAGE)

        session = self._establish_session(user, self._host_context())
        return LoginResult(
            session=session, must_change_password=user.must_change_password
        )

    def _establish_session(self, user: User, host: str) -> Session:
        """Create the in-memory and persisted session for a verified user."""
        assert user.id is not None  # guarded by callers
        permissions: PermissionSet = self._users.permissions_for_user(user.id)
        session = self._sessions.create(
            user_id=user.id,
            username=user.username,
            role=user.role_name or "USER",
            permissions=permissions,
            host_context=host,
        )
        try:
            session.db_session_id = self._users.create_session(
                user_id=user.id,
                token_fingerprint=token_fingerprint(session.token),
                host_context=host,
                expires_at=session.expires_at,
            )
        except Exception:  # noqa: BLE001 - a persistence hiccup must not block work
            LOGGER.exception("Could not persist the session record.")

        self._users.register_successful_login(user.id, host)
        self._users.record_login_attempt(
            username=user.username, user_id=user.id, successful=True,
            reason="password", host_context=host,
        )
        self._audit.record(
            AuditAction.LOGIN_SUCCESS,
            session=session,
            category=AuditCategory.AUTHENTICATION,
            detail=f"Signed in as {user.role_name or 'USER'} from {host or 'unknown host'}.",
        )
        LOGGER.info("User '%s' signed in (role=%s).", user.username, user.role_name)
        return session

    def _record_failure(
        self, username: str, user_id: int | None, reason: str, host: str
    ) -> None:
        """Record a failed attempt in both the attempt log and the audit trail."""
        try:
            self._users.record_login_attempt(
                username=username, user_id=user_id, successful=False,
                reason=reason, host_context=host,
            )
        except Exception:  # noqa: BLE001
            LOGGER.exception("Could not record a failed login attempt.")
        self._audit.record(
            AuditAction.LOGIN_FAILED,
            user_id=user_id,
            username=username,
            category=AuditCategory.AUTHENTICATION,
            result="FAILURE",
            detail=f"Sign-in failed ({reason}) from {host or 'unknown host'}.",
        )
        LOGGER.warning("Failed sign-in for '%s' (%s).", username, reason)

    def _is_locked(self, user: User) -> bool:
        """True when a lockout is currently in force, clearing expired ones."""
        if not user.is_locked:
            return False
        if user.locked_until and utcnow() >= user.locked_until and user.id:
            self._users.set_locked(user.id, False, None)
            return False
        return True

    # ------------------------------------------------------------------
    # Sign out and password change
    # ------------------------------------------------------------------
    def logout(self, session: Session | None, reason: str = "logout") -> None:
        """End a session in memory and in the database."""
        if session is None:
            return
        self._sessions.invalidate(session.token)
        if session.db_session_id:
            try:
                self._users.end_session(session.db_session_id, reason)
            except Exception:  # noqa: BLE001
                LOGGER.exception("Could not close the persisted session record.")
        self._audit.record(
            AuditAction.LOGOUT,
            session=session,
            category=AuditCategory.AUTHENTICATION,
            detail=f"Signed out ({reason}).",
        )

    def terminate_user_sessions(
        self, user_id: int, actor: Session | None, reason: str = "administrative"
    ) -> int:
        """Force-log-out every session of one account (§70)."""
        terminated = self._sessions.invalidate_user(user_id)
        try:
            self._users.end_sessions_for_user(user_id, reason)
        except Exception:  # noqa: BLE001
            LOGGER.exception("Could not close persisted sessions for user %s", user_id)
        self._audit.record(
            AuditAction.SESSION_TERMINATED,
            session=actor,
            category=AuditCategory.ADMINISTRATION,
            target_type="user",
            target_id=user_id,
            detail=f"Terminated {len(terminated)} active session(s) ({reason}).",
        )
        return len(terminated)

    def change_own_password(
        self, session: Session, current_password: str, new_password: str
    ) -> None:
        """Change the signed-in user's own password.

        Raises:
            AuthenticationError: when the current password does not verify.
            ValidationFailedError: when the new password fails policy.
        """
        stored_hash, _ = self._users.get_password_hash(session.user_id)
        if not self._passwords.verify(current_password, stored_hash):
            self._audit.record(
                AuditAction.PASSWORD_CHANGED,
                session=session,
                category=AuditCategory.AUTHENTICATION,
                result="FAILURE",
                detail="Password change refused: current password incorrect.",
            )
            raise AuthenticationError(
                user_message="Your current password is not correct."
            )
        try:
            validate_password(
                new_password, min_length=self._policy.password_min_length
            )
        except ValidationError as exc:
            raise ValidationFailedError(str(exc), user_message=str(exc)) from exc
        if current_password == new_password:
            raise ValidationFailedError(
                user_message="The new password must be different from the current one."
            )

        hashed = self._passwords.hash(new_password)
        self._users.set_password(
            session.user_id, hashed.hash, hashed.algorithm, must_change=False
        )
        self._audit.record(
            AuditAction.PASSWORD_CHANGED,
            session=session,
            category=AuditCategory.AUTHENTICATION,
            target_type="user",
            target_id=session.user_id,
            detail="Password changed by the account owner.",
        )

    def purge_expired_sessions(self) -> int:
        """Drop expired sessions from memory and close their database rows."""
        removed = self._sessions.purge_expired()
        try:
            self._users.expire_stale_sessions()
        except Exception:  # noqa: BLE001
            LOGGER.debug("Could not expire stale session rows.", exc_info=True)
        return removed
