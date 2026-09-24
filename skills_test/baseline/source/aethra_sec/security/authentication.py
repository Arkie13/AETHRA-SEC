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
from typing import Any
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
from aethra_sec.security.lockout import (
    ALERT_THRESHOLD,
    ALERT_WINDOW_MINUTES,
    FAILURES_BEFORE_LOCK,
    LockoutState,
    evaluate,
    format_remaining,
)
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

    A sign-in has exactly two outcomes: a session, or an exception describing
    why there is none. There is no intermediate state in which a password has
    been accepted but the operator is not yet signed in - that state existed
    when a second factor did, and it went with it.
    """

    session: Session | None = None
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
        policy: AuthenticationPolicy | None = None,
        notifications: Any = None,
    ) -> None:
        """Wire the service to its collaborators.

        ``notifications`` is optional so the service can be constructed in a
        test or a setup script without one. When it is absent the lockout still
        works in full; only the administrator's alert is skipped.
        """
        self._users = users
        self._sessions = sessions
        self._passwords = passwords
        self._audit = audit
        self._notifications = notifications
        self._policy = policy or AuthenticationPolicy()
        self._sessions.set_timeout(self._policy.session_timeout_minutes)

    @property
    def policy(self) -> AuthenticationPolicy:
        """The active authentication policy."""
        return self._policy

    def attach_notifications(self, notifications: Any) -> None:
        """Give the service somewhere to raise administrator alerts.

        Set after construction because the notification service is built later
        in the start-up order. Until it is attached the lockout works in full
        and only the alert is skipped, which is the right way round: the
        control that refuses sign-in must never depend on the one that reports
        it.
        """
        self._notifications = notifications

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
                but cannot be used. These are distinguishable from a credential
                failure because the operator needs to know to contact an
                administrator - and they are reachable only *after* the
                password has verified, so neither can be used to discover
                whether an account exists.
        """
        host = self._host_context()
        candidate = (username or "").strip()

        if not candidate or not password:
            self._record_failure(candidate, None, "empty_credentials", host)
            raise AuthenticationError(user_message=GENERIC_FAILURE_MESSAGE)

        # The throttle is checked here, before the password is looked at, and
        # it is the reason a correct password cannot get in during a lock.
        #
        # Checking it first is safe *because* it is keyed on the submitted name
        # rather than on an account: an unknown username accumulates failures
        # and locks in exactly the same way, so the refusal discloses nothing
        # about whether the account exists. The per-account lock below is a
        # different control and stays where it is, after verification.
        lock = self._lockout_for(candidate)
        if lock.locked:
            self._record_failure(candidate, None, "throttled", host)
            self._audit.record(
                AuditAction.LOGIN_LOCKED,
                username=candidate,
                category=AuditCategory.AUTHENTICATION,
                result="DENIED",
                detail=(
                    f"Sign-in refused: {lock.failures} consecutive failed "
                    f"attempts; locked for {lock.seconds}s, "
                    f"{lock.remaining(utcnow())}s remaining."
                ),
            )
            raise AccountLockedError(user_message=self._lockout_message(lock))

        user = self._users.get_by_username(candidate)
        if user is None or user.id is None:
            # Unknown account: record the attempt, answer with the generic
            # message, and do not reveal that the username does not exist.
            # It escalates and alerts exactly as a real name does - anything
            # less would make the *absence* of a lock the tell.
            self._record_failure(candidate, None, "unknown_user", host)
            unknown_lock = self._lockout_for(candidate)
            self._raise_security_alert(candidate, None, unknown_lock, host)
            if unknown_lock.locked:
                raise AccountLockedError(
                    user_message=self._lockout_message(unknown_lock)
                )
            raise AuthenticationError(user_message=GENERIC_FAILURE_MESSAGE)

        stored_hash, _algorithm = self._users.get_password_hash(user.id)
        if not self._passwords.verify(password, stored_hash):
            self._users.register_failed_login(user.id)
            self._record_failure(candidate, user.id, "bad_password", host)
            # Re-read after recording, so the decision is made from the row
            # this attempt just wrote rather than from a stale count.
            lock = self._lockout_for(candidate)
            if lock.locked:
                self._users.set_locked(user.id, True, lock.locked_until)
                self._audit.record(
                    AuditAction.LOGIN_LOCKED,
                    user_id=user.id,
                    username=user.username,
                    category=AuditCategory.AUTHENTICATION,
                    result="DENIED",
                    detail=(
                        f"Sign-in locked after {lock.failures} consecutive "
                        f"failed attempts; lock lasts {lock.seconds}s "
                        f"(escalation level {lock.level})."
                    ),
                )
            self._raise_security_alert(candidate, user.id, lock, host)
            if lock.locked:
                raise AccountLockedError(user_message=self._lockout_message(lock))
            raise AuthenticationError(user_message=GENERIC_FAILURE_MESSAGE)

        # The lockout is disclosed only to someone who has just proved they
        # know the password. Checked before verification it was an enumeration
        # oracle: six wrong guesses against any name, and the reply told the
        # guesser whether that account existed. A wrong password now gets the
        # same generic answer whatever the account's state, and the operator
        # who does know their password still learns why they cannot get in.
        if self._is_locked(user):
            self._record_failure(candidate, user.id, "account_locked", host)
            self._audit.record(
                AuditAction.LOGIN_LOCKED,
                user_id=user.id,
                username=user.username,
                category=AuditCategory.AUTHENTICATION,
                result="DENIED",
                detail=(
                    "Sign-in refused: the account is locked. The password "
                    "supplied was correct."
                ),
            )
            raise AccountLockedError()

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

        session = self._establish_session(user, host)
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

    # ------------------------------------------------------------------
    # Lockout
    # ------------------------------------------------------------------
    def _lockout_for(self, username: str) -> LockoutState:
        """The lock state for a submitted username, from recorded attempts.

        A database failure here must not hand out a free pass, but neither
        should it lock everyone out of the console. It resolves to "not
        locked" and is logged: the password check still has to pass, and the
        per-account lock below is a second line.
        """
        try:
            failures, last_at = self._users.consecutive_failures(username)
        except Exception:  # noqa: BLE001
            LOGGER.exception("Could not read the sign-in attempt history.")
            return LockoutState()
        return evaluate(failures, last_at, utcnow())

    @staticmethod
    def _lockout_message(lock: LockoutState) -> str:
        """What the operator is told while a lock is in force.

        Names the wait and nothing else - not the threshold, not the schedule,
        not whether the account exists.
        """
        remaining = lock.remaining(utcnow())
        return (
            "Too many unsuccessful login attempts. "
            f"Try again in {format_remaining(remaining)}."
        )

    def lockout_status(self, username: str) -> tuple[bool, int]:
        """Whether sign-in is currently locked, and for how many seconds.

        Read by the sign-in screen to drive its countdown. The screen only
        *displays* this; every decision is made in :meth:`login`, so a tampered
        or stopped client clock changes nothing about what the server accepts.
        """
        lock = self._lockout_for((username or "").strip())
        return lock.locked, lock.remaining(utcnow())

    # ------------------------------------------------------------------
    # Administrator alerting
    # ------------------------------------------------------------------
    def _raise_security_alert(
        self,
        username: str,
        user_id: int | None,
        lock: LockoutState,
        host: str,
    ) -> None:
        """Tell an administrator about a real run of failed sign-ins.

        Raised only from attempts this service actually recorded, and only once
        the run reaches :data:`ALERT_THRESHOLD` inside the window. Every figure
        in the notification is counted from ``login_attempts``; none of it is
        composed.

        Deduplicated rather than repeated: eight failures produce one alert,
        not eight. A further alert is raised only when the lock escalates,
        which is the point at which the situation has genuinely changed.
        """
        if self._notifications is None:
            return
        window_start = utcnow() - timedelta(minutes=ALERT_WINDOW_MINUTES)
        try:
            recent = self._users.failed_attempts_since(username, window_start)
        except Exception:  # noqa: BLE001
            LOGGER.debug("Could not count recent failures.", exc_info=True)
            return
        if recent < ALERT_THRESHOLD:
            return

        reference = f"login-failures:{username[:48]}"
        try:
            if self._notifications.security_alert_exists(reference, window_start):
                # One already stands for this window. It is replaced only when
                # the lock escalates, so a sustained attack updates the
                # administrator instead of burying them.
                if not (lock.locked and lock.failures % FAILURES_BEFORE_LOCK == 0):
                    return
                if self._notifications.security_alert_exists(
                    f"{reference}:L{lock.level}", window_start
                ):
                    return
                reference = f"{reference}:L{lock.level}"
        except Exception:  # noqa: BLE001
            LOGGER.debug("Could not check for an existing alert.", exc_info=True)
            return

        detail = (
            f"{recent} failed sign-in attempt(s) for '{username[:64]}' in the "
            f"last {ALERT_WINDOW_MINUTES} minutes"
            + (f" from {host}" if host else "")
            + (
                f". Sign-in is locked for {lock.seconds}s."
                if lock.locked
                else "."
            )
        )
        try:
            self._notifications.raise_security_alert(
                title="Multiple failed login attempts",
                message=detail,
                reference=reference,
                user_id=user_id,
            )
        except Exception:  # noqa: BLE001
            LOGGER.debug("Could not raise the sign-in alert.", exc_info=True)
            return

        self._audit.record(
            AuditAction.MULTIPLE_LOGIN_FAILURES,
            user_id=user_id,
            username=username,
            category=AuditCategory.AUTHENTICATION,
            result="DENIED",
            detail=detail,
        )
        LOGGER.warning("Sign-in security alert raised: %s", detail)

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
