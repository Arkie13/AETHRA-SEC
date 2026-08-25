"""Administrator-approved password recovery (§6, §62, §70).

The problem this solves is the one every deployment hits: an operator forgets
their password and there is no mail server, no help-desk portal and no
self-service reset that could be trusted on a security console anyway.

The workflow, and why each step exists:

1. **The operator raises a request from the sign-in screen.** No credential is
   accepted and nothing changes; a row is queued for review. The screen shows
   the same acknowledgement whether or not the account exists, so the form
   cannot be used to enumerate usernames (§62).
2. **An administrator reviews it.** They are the identity check - they know who
   asked, and the request records where and when it came from.
3. **Approval mints a one-time code.** It is shown to the administrator once,
   stored only as a SHA-256 digest, expires in minutes rather than days, and
   survives exactly one use.
4. **The operator sets a new password with that code.** Until this point the
   account's credential is untouched: an unapproved request confers nothing.

Every step is audited. Nothing here can be reached without either a permission
check (review, approve, reject) or a valid one-time code (completion).
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta

from aethra_sec.core.errors import (
    AuthenticationError,
    ValidationFailedError,
)
from aethra_sec.core.permissions import Permission
from aethra_sec.core.session import Session
from aethra_sec.database.repositories.password_resets import PasswordResetRepository
from aethra_sec.database.repositories.users import UserRepository
from aethra_sec.models.user import PasswordResetRequest, ResetStatus
from aethra_sec.security.audit import AuditAction, AuditCategory, AuditService
from aethra_sec.security.authentication import AuthenticationService
from aethra_sec.security.password import (
    PasswordHashService,
    code_fingerprint,
    generate_recovery_code,
)
from aethra_sec.security.rbac import AccessControl
from aethra_sec.utils.logging import get_logger
from aethra_sec.utils.timeutil import utcnow
from aethra_sec.utils.validation import (
    ValidationError,
    validate_email,
    validate_password,
    validate_username,
)

LOGGER = get_logger("services.recovery")

#: Shown for every reset request, valid or not. Identical wording is what stops
#: the form from confirming whether an account exists (§62).
REQUEST_ACKNOWLEDGEMENT = (
    "If that account exists, a password-reset request has been queued for "
    "administrator review. An administrator will verify who you are and give "
    "you a one-time recovery code. Your password has not been changed."
)

#: Shown for every failed code redemption, whatever the underlying reason.
GENERIC_CODE_FAILURE = (
    "That recovery code is not valid for this account, or the approval has "
    "expired. Ask an administrator to approve a new request."
)


@dataclass
class RecoveryPolicy:
    """Tunable limits for the recovery workflow, loaded from settings."""

    request_ttl_hours: int = 24
    code_ttl_minutes: int = 60
    max_code_attempts: int = 5
    max_requests_per_day: int = 3


@dataclass
class Approval:
    """The result of approving a request.

    ``code`` is the only time the plaintext exists after generation. The caller
    shows it once to the approving administrator and does not retain it.
    """

    request_id: int
    username: str
    code: str
    expires_at: datetime


class PasswordRecoveryService:
    """Queues, reviews and consumes password-reset requests."""

    def __init__(
        self,
        requests: PasswordResetRepository,
        users: UserRepository,
        passwords: PasswordHashService,
        authentication: AuthenticationService,
        audit: AuditService,
        access: AccessControl,
        policy: RecoveryPolicy | None = None,
    ) -> None:
        """Wire the service to its collaborators."""
        self._requests = requests
        self._users = users
        self._passwords = passwords
        self._authentication = authentication
        self._audit = audit
        self._access = access
        self._policy = policy or RecoveryPolicy()

    @property
    def policy(self) -> RecoveryPolicy:
        """The active recovery policy."""
        return self._policy

    def apply_policy(self, policy: RecoveryPolicy) -> None:
        """Replace the policy (called when an administrator edits settings)."""
        self._policy = policy

    # ------------------------------------------------------------------
    # Step 1: the sign-in screen raises a request (unauthenticated)
    # ------------------------------------------------------------------
    def request_reset(
        self,
        username: str,
        *,
        reason: str = "",
        contact: str = "",
        host_context: str = "",
    ) -> str:
        """Queue a password-reset request for administrator review.

        This is one of the two entry points that does not require a session -
        the caller has, by definition, no way to sign in. It therefore changes
        no credential and reveals nothing: the return value is the same
        acknowledgement in every case, and the real outcome goes to the audit
        trail where an administrator can see it.

        Returns:
            :data:`REQUEST_ACKNOWLEDGEMENT`, for display on the sign-in screen.
        """
        try:
            clean_username = validate_username(username)
        except ValidationError:
            self._audit_request_failure(username, "malformed username", host_context)
            return REQUEST_ACKNOWLEDGEMENT

        clean_reason = " ".join(str(reason or "").split())[:255]
        try:
            clean_contact = validate_email(contact)
        except ValidationError:
            clean_contact = ""

        user = self._users.get_by_username(clean_username)
        if user is None or user.id is None:
            self._audit_request_failure(clean_username, "unknown account", host_context)
            return REQUEST_ACKNOWLEDGEMENT
        if not user.is_active:
            self._audit_request_failure(
                clean_username, "account is not active", host_context, user_id=user.id
            )
            return REQUEST_ACKNOWLEDGEMENT

        existing = self._requests.open_for_user(user.id)
        if existing is not None and not existing.has_expired(utcnow()):
            self._audit.record(
                AuditAction.PASSWORD_RESET_REQUESTED,
                user_id=user.id,
                username=clean_username,
                category=AuditCategory.AUTHENTICATION,
                result="WARNING",
                target_type="password_reset",
                target_id=existing.id or "",
                detail=(
                    f"Reset request ignored: request #{existing.id} for "
                    f"'{clean_username}' is already {existing.status}."
                ),
            )
            return REQUEST_ACKNOWLEDGEMENT

        window = utcnow() - timedelta(hours=24)
        if self._requests.recent_request_count(user.id, window) >= max(
            1, self._policy.max_requests_per_day
        ):
            self._audit.record(
                AuditAction.PASSWORD_RESET_REQUESTED,
                user_id=user.id,
                username=clean_username,
                category=AuditCategory.AUTHENTICATION,
                result="DENIED",
                detail=(
                    f"Reset request refused: '{clean_username}' has reached the "
                    f"limit of {self._policy.max_requests_per_day} request(s) in "
                    "24 hours."
                ),
            )
            return REQUEST_ACKNOWLEDGEMENT

        expires_at = utcnow() + timedelta(
            hours=max(1, self._policy.request_ttl_hours)
        )
        request_id = self._requests.create(
            user_id=user.id,
            username=clean_username,
            reason=clean_reason,
            contact=clean_contact,
            host_context=host_context,
            expires_at=expires_at,
        )
        self._audit.record(
            AuditAction.PASSWORD_RESET_REQUESTED,
            user_id=user.id,
            username=clean_username,
            category=AuditCategory.AUTHENTICATION,
            target_type="password_reset",
            target_id=request_id,
            detail=(
                f"Password-reset request #{request_id} raised for "
                f"'{clean_username}' from {host_context or 'unknown host'}. "
                "Awaiting administrator review; the password is unchanged."
            ),
        )
        LOGGER.info(
            "Password-reset request %s queued for '%s'.", request_id, clean_username
        )
        return REQUEST_ACKNOWLEDGEMENT

    def _audit_request_failure(
        self,
        username: str,
        why: str,
        host_context: str,
        *,
        user_id: int | None = None,
    ) -> None:
        """Record a request that was not queued, without telling the caller."""
        self._audit.record(
            AuditAction.PASSWORD_RESET_REQUESTED,
            user_id=user_id,
            username=str(username)[:64],
            category=AuditCategory.AUTHENTICATION,
            result="FAILURE",
            detail=(
                f"Reset request not queued ({why}) for '{username}' from "
                f"{host_context or 'unknown host'}."
            ),
        )

    # ------------------------------------------------------------------
    # Step 2: an administrator reviews the queue
    # ------------------------------------------------------------------
    def list_requests(
        self, session: Session, *, status: str = "", limit: int = 200
    ) -> list[PasswordResetRequest]:
        """Requests an administrator may act on, newest first.

        Args:
            status: one of :class:`ResetStatus`, or empty for every state.
        """
        self._access.require(session, Permission.USER_RESET_APPROVE)
        statuses = (status,) if status in ResetStatus.ALL else ()
        return self._requests.list_requests(statuses=statuses, limit=limit)

    def pending_count(self, session: Session) -> int:
        """How many requests are waiting for a decision."""
        self._access.require(session, Permission.USER_RESET_APPROVE)
        return self._requests.count_by_status(ResetStatus.PENDING)

    def approve(
        self, session: Session, request_id: int, *, note: str = ""
    ) -> Approval:
        """Approve a pending request and mint its one-time code.

        The administrator hands the returned code to the account owner through
        a channel they trust. Only its digest is stored.

        Raises:
            PermissionDeniedError: the session may not approve requests.
            ValidationFailedError: the request is unknown, expired, or is no
                longer pending.
        """
        live = self._access.require(
            session, Permission.USER_RESET_APPROVE, target=str(request_id)
        )
        request = self._require_pending(request_id)

        code = generate_recovery_code()
        expires_at = utcnow() + timedelta(
            minutes=max(5, self._policy.code_ttl_minutes)
        )
        changed = self._requests.approve(
            request_id,
            reviewer_id=live.user_id,
            note=note,
            code_hash=code_fingerprint(code),
            code_expires_at=expires_at,
        )
        if not changed:
            # Another administrator decided it between the read and the write.
            raise ValidationFailedError(
                "Request is no longer pending.",
                user_message=(
                    "That request was already decided by another "
                    "administrator. Refresh the queue."
                ),
            )

        self._audit.record(
            AuditAction.PASSWORD_RESET_APPROVED,
            session=live,
            category=AuditCategory.ADMINISTRATION,
            target_type="password_reset",
            target_id=request_id,
            detail=(
                f"Approved password-reset request #{request_id} for "
                f"'{request.username}'. A one-time code was issued and expires "
                f"in {self._policy.code_ttl_minutes} minute(s)."
                + (f" Note: {note}" if note else "")
            ),
        )
        LOGGER.info(
            "Password-reset request %s approved for '%s'.",
            request_id,
            request.username,
        )
        return Approval(
            request_id=request_id,
            username=request.username,
            code=code,
            expires_at=expires_at,
        )

    def reject(self, session: Session, request_id: int, *, note: str = "") -> None:
        """Reject an open request, revoking any code already issued.

        Raises:
            PermissionDeniedError, ValidationFailedError.
        """
        live = self._access.require(
            session, Permission.USER_RESET_APPROVE, target=str(request_id)
        )
        request = self._requests.get(request_id)
        if request is None:
            raise ValidationFailedError(
                "Reset request not found.",
                user_message="That request no longer exists.",
            )
        if request.status not in ResetStatus.OPEN:
            raise ValidationFailedError(
                f"Request is {request.status}.",
                user_message=(
                    f"That request is already {request.status.lower()} and "
                    "cannot be rejected."
                ),
            )

        self._requests.reject(request_id, reviewer_id=live.user_id, note=note)
        self._audit.record(
            AuditAction.PASSWORD_RESET_REJECTED,
            session=live,
            category=AuditCategory.ADMINISTRATION,
            target_type="password_reset",
            target_id=request_id,
            detail=(
                f"Rejected password-reset request #{request_id} for "
                f"'{request.username}'. The password is unchanged."
                + (f" Note: {note}" if note else "")
            ),
        )

    def _require_pending(self, request_id: int) -> PasswordResetRequest:
        """Load a request that is genuinely still awaiting a decision."""
        request = self._requests.get(request_id)
        if request is None:
            raise ValidationFailedError(
                "Reset request not found.",
                user_message="That request no longer exists.",
            )
        if not request.is_pending:
            raise ValidationFailedError(
                f"Request is {request.status}.",
                user_message=(
                    f"That request is already {request.status.lower()}. Only a "
                    "pending request can be approved."
                ),
            )
        if request.has_expired(utcnow()):
            self._requests.expire_stale()
            raise ValidationFailedError(
                "Reset request expired.",
                user_message=(
                    "That request has expired. Ask the operator to raise a new "
                    "one from the sign-in screen."
                ),
            )
        return request

    # ------------------------------------------------------------------
    # Step 4: the operator redeems the code (unauthenticated)
    # ------------------------------------------------------------------
    def complete_reset(
        self, username: str, code: str, new_password: str, *, host_context: str = ""
    ) -> None:
        """Set a new password using an approved one-time code.

        The second unauthenticated entry point, and the only one that changes a
        credential. It requires an approval that is still live, a code that
        matches its stored digest, and a password that satisfies policy. The
        approval is consumed atomically, so a code works exactly once.

        Raises:
            AuthenticationError: the code is wrong, expired, exhausted, or
                there is no approval for the account. The message is identical
                in every case.
            ValidationFailedError: the new password fails policy.
        """
        try:
            clean_username = validate_username(username)
        except ValidationError as exc:
            raise AuthenticationError(
                str(exc), user_message=GENERIC_CODE_FAILURE
            ) from exc

        request = self._requests.approved_for_username(clean_username)
        if request is None or request.id is None:
            self._audit_code_failure(clean_username, "no approved request", host_context)
            raise AuthenticationError(user_message=GENERIC_CODE_FAILURE)

        if request.has_expired(utcnow()):
            self._requests.expire_stale()
            self._audit_code_failure(
                clean_username, "approval expired", host_context, request=request
            )
            raise AuthenticationError(user_message=GENERIC_CODE_FAILURE)

        stored = self._requests.code_hash_for(request.id)
        if not stored or not secrets.compare_digest(stored, code_fingerprint(code)):
            self._register_wrong_code(request, clean_username, host_context)
            raise AuthenticationError(user_message=GENERIC_CODE_FAILURE)

        user = self._users.get_by_id(request.user_id)
        if user is None or user.id is None or not user.is_active:
            self._audit_code_failure(
                clean_username, "account unavailable", host_context, request=request
            )
            raise AuthenticationError(user_message=GENERIC_CODE_FAILURE)

        try:
            validate_password(
                new_password,
                min_length=self._authentication.policy.password_min_length,
            )
        except ValidationError as exc:
            raise ValidationFailedError(str(exc), user_message=str(exc)) from exc

        current_hash, _algorithm = self._users.get_password_hash(user.id)
        if current_hash and self._passwords.verify(new_password, current_hash):
            raise ValidationFailedError(
                "New password matches the current one.",
                user_message=(
                    "The new password must be different from your current one."
                ),
            )

        # Claim the approval before touching the credential: if two attempts
        # race, exactly one of them updates a row and the other is refused.
        if not self._requests.complete(request.id):
            self._audit_code_failure(
                clean_username, "approval already consumed", host_context,
                request=request,
            )
            raise AuthenticationError(user_message=GENERIC_CODE_FAILURE)

        hashed = self._passwords.hash(new_password)
        self._users.set_password(
            user.id, hashed.hash, hashed.algorithm, must_change=False
        )
        self._audit.record(
            AuditAction.PASSWORD_RESET_COMPLETED,
            user_id=user.id,
            username=clean_username,
            category=AuditCategory.AUTHENTICATION,
            target_type="password_reset",
            target_id=request.id,
            detail=(
                f"Password set by the account owner using approved request "
                f"#{request.id} (approved by "
                f"{request.reviewer_username or 'an administrator'}) from "
                f"{host_context or 'unknown host'}. The code is now spent."
            ),
        )
        self._authentication.terminate_user_sessions(
            user.id, None, reason="password recovered"
        )
        LOGGER.info("Password recovered for '%s' via request %s.", clean_username, request.id)

    def _register_wrong_code(
        self, request: PasswordResetRequest, username: str, host_context: str
    ) -> None:
        """Count a wrong code and revoke the approval once the limit is hit."""
        if request.id is None:
            return
        attempts = self._requests.register_code_attempt(request.id)
        limit = max(1, self._policy.max_code_attempts)
        if attempts >= limit:
            # No reviewer is recorded: nobody decided this, the limit did. Who
            # approved it in the first place is already in the audit trail.
            self._requests.reject(
                request.id,
                reviewer_id=None,
                note=(
                    f"Revoked automatically after {attempts} incorrect "
                    "recovery code(s)."
                ),
            )
            self._audit.record(
                AuditAction.PASSWORD_RESET_REJECTED,
                user_id=request.user_id,
                username=username,
                category=AuditCategory.AUTHENTICATION,
                result="DENIED",
                target_type="password_reset",
                target_id=request.id,
                detail=(
                    f"Approval #{request.id} for '{username}' revoked after "
                    f"{attempts} incorrect recovery code(s) from "
                    f"{host_context or 'unknown host'}."
                ),
            )
            return
        self._audit_code_failure(
            username,
            f"incorrect code (attempt {attempts} of {limit})",
            host_context,
            request=request,
        )

    def _audit_code_failure(
        self,
        username: str,
        why: str,
        host_context: str,
        *,
        request: PasswordResetRequest | None = None,
    ) -> None:
        """Record a refused code redemption. The code itself is never logged."""
        self._audit.record(
            AuditAction.PASSWORD_RESET_COMPLETED,
            user_id=request.user_id if request else None,
            username=str(username)[:64],
            category=AuditCategory.AUTHENTICATION,
            result="FAILURE",
            target_type="password_reset",
            target_id=(request.id if request else "") or "",
            detail=(
                f"Recovery code refused for '{username}' ({why}) from "
                f"{host_context or 'unknown host'}."
            ),
        )

    # ------------------------------------------------------------------
    # Housekeeping
    # ------------------------------------------------------------------
    def expire_stale(self) -> int:
        """Expire timed-out requests and approvals.

        Run by the background scheduler, so an approval stops working when its
        deadline passes even if nobody opens the queue.
        """
        try:
            expired = self._requests.expire_stale()
        except Exception:  # noqa: BLE001 - housekeeping must not break startup
            LOGGER.debug("Could not expire stale reset requests.", exc_info=True)
            return 0
        if expired:
            self._audit.record(
                AuditAction.PASSWORD_RESET_EXPIRED,
                category=AuditCategory.AUTHENTICATION,
                detail=f"{expired} password-reset request(s) expired unused.",
            )
        return expired
