"""Administrative user management (§70).

Every operation is permission-checked and audited. Two safeguards protect the
installation from being locked out: the last active administrator cannot be
deactivated or demoted, and an account cannot deactivate itself.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from aethra_sec.core.errors import ValidationFailedError
from aethra_sec.core.permissions import Permission
from aethra_sec.core.session import Session
from aethra_sec.database.repositories.users import UserRepository
from aethra_sec.models.user import LoginAttempt, Role, User, UserSessionRecord
from aethra_sec.security.audit import AuditAction, AuditCategory, AuditService
from aethra_sec.security.authentication import AuthenticationService
from aethra_sec.security.password import (
    PasswordHashService,
    generate_temporary_password,
)
from aethra_sec.security.rbac import AccessControl
from aethra_sec.utils.logging import get_logger
from aethra_sec.utils.validation import (
    ValidationError,
    validate_email,
    validate_password,
    validate_username,
)

LOGGER = get_logger("services.users")


@dataclass
class CreatedAccount:
    """The outcome of registering a new account.

    ``password`` is the credential to hand to the new operator. It exists only
    for as long as the dialog that shows it: nothing stores it, logs it or
    writes it to the audit trail.
    """

    user_id: int
    username: str
    role_name: str
    password: str
    generated: bool
    must_change_password: bool


class UserService:
    """Creates and maintains accounts on behalf of an administrator."""

    def __init__(
        self,
        users: UserRepository,
        passwords: PasswordHashService,
        authentication: AuthenticationService,
        audit: AuditService,
        access: AccessControl,
    ) -> None:
        """Wire the service to its collaborators."""
        self._users = users
        self._passwords = passwords
        self._authentication = authentication
        self._audit = audit
        self._access = access

    # ------------------------------------------------------------------
    # Reads
    # ------------------------------------------------------------------
    def list_users(self, session: Session) -> list[User]:
        """List every account."""
        self._access.require(session, Permission.USER_MANAGE)
        return self._users.list_users()

    def get(self, session: Session, user_id: int) -> User | None:
        """Fetch one account."""
        self._access.require(session, Permission.USER_MANAGE, target=str(user_id))
        return self._users.get_by_id(user_id)

    def roles(self, session: Session) -> list[Role]:
        """Available roles and their permissions."""
        self._access.require(session, Permission.USER_MANAGE)
        return self._users.list_roles()

    def login_history(
        self, session: Session, user_id: int | None = None, limit: int = 100
    ) -> list[LoginAttempt]:
        """Login attempts, optionally for one account."""
        self._access.require(session, Permission.USER_MANAGE)
        return self._users.list_login_attempts(user_id=user_id, limit=limit)

    def active_sessions(self, session: Session) -> list[UserSessionRecord]:
        """Currently signed-in sessions."""
        self._access.require(session, Permission.USER_MANAGE)
        return self._users.list_sessions(active_only=True)

    # ------------------------------------------------------------------
    # Writes
    # ------------------------------------------------------------------
    def create_user(
        self,
        session: Session,
        *,
        username: str,
        password: str = "",
        role_name: str,
        full_name: str = "",
        email: str = "",
        must_change_password: bool = True,
    ) -> CreatedAccount:
        """Register a new account on behalf of an administrator (§70).

        Args:
            password: the initial credential, or empty to generate one that is
                guaranteed to satisfy the policy.

        Returns:
            The new account and the password to hand over, once.

        Raises:
            PermissionDeniedError: the session may not manage users.
            ValidationFailedError: a field is invalid, the username is taken,
                or the role does not exist.
        """
        live = self._access.require(session, Permission.USER_MANAGE, target=username)
        generated = not password
        effective_password = password or generate_temporary_password()
        try:
            clean_username = validate_username(username)
            clean_email = validate_email(email)
            validate_password(
                effective_password,
                min_length=self._authentication.policy.password_min_length,
            )
        except ValidationError as exc:
            raise ValidationFailedError(str(exc), user_message=str(exc)) from exc

        if self._users.get_by_username(clean_username):
            raise ValidationFailedError(
                "Username already exists.",
                user_message=f"The username '{clean_username}' is already in use.",
            )

        role = self._users.get_role_by_name(role_name)
        if role is None or role.id is None:
            raise ValidationFailedError(
                f"Unknown role '{role_name}'.",
                user_message=f"'{role_name}' is not a valid role.",
            )

        hashed = self._passwords.hash(effective_password)
        user_id = self._users.create_user(
            username=clean_username,
            password_hash=hashed.hash,
            password_algorithm=hashed.algorithm,
            role_id=role.id,
            full_name=full_name.strip()[:128],
            email=clean_email,
            created_by=live.user_id,
            must_change_password=must_change_password,
        )
        self._audit.record(
            AuditAction.USER_CREATED,
            session=live,
            category=AuditCategory.ADMINISTRATION,
            target_type="user",
            target_id=user_id,
            detail=(
                f"Created account '{clean_username}' with role {role.name}. "
                f"Initial password was {'generated' if generated else 'set by the administrator'}; "
                f"change at next sign-in: {'required' if must_change_password else 'not required'}."
            ),
        )
        LOGGER.info("Account '%s' created with role %s.", clean_username, role.name)
        return CreatedAccount(
            user_id=user_id,
            username=clean_username,
            role_name=role.name,
            password=effective_password,
            generated=generated,
            must_change_password=must_change_password,
        )

    def update_user(
        self,
        session: Session,
        user_id: int,
        *,
        full_name: str,
        email: str,
        role_name: str,
        is_active: bool,
    ) -> None:
        """Update an account's profile, role and active state."""
        live = self._access.require(session, Permission.USER_MANAGE, target=str(user_id))
        target = self._users.get_by_id(user_id)
        if target is None:
            raise ValidationFailedError(
                "User not found.", user_message="That account no longer exists."
            )
        try:
            clean_email = validate_email(email)
        except ValidationError as exc:
            raise ValidationFailedError(str(exc), user_message=str(exc)) from exc

        role = self._users.get_role_by_name(role_name)
        if role is None or role.id is None:
            raise ValidationFailedError(
                f"Unknown role '{role_name}'.",
                user_message=f"'{role_name}' is not a valid role.",
            )

        self._guard_last_admin(target, new_role=role.name, new_active=is_active)
        if not is_active and live.user_id == user_id:
            raise ValidationFailedError(
                "Self-deactivation refused.",
                user_message="You cannot deactivate your own account.",
            )

        previous_role = (target.role_name or "").upper()
        self._users.update_profile(
            user_id,
            full_name=full_name.strip()[:128],
            email=clean_email,
            role_id=role.id,
            is_active=is_active,
        )
        if previous_role != role.name.upper():
            # A role change is an authorisation change, so it is audited in its
            # own right rather than buried inside a profile update (§32).
            self._audit.record(
                AuditAction.USER_ROLE_CHANGED,
                session=live,
                category=AuditCategory.ADMINISTRATION,
                target_type="user",
                target_id=user_id,
                detail=(
                    f"Role of '{target.username}' changed from "
                    f"{previous_role or 'none'} to {role.name}. The new "
                    "permissions apply at the account's next sign-in."
                ),
            )
            self._authentication.terminate_user_sessions(
                user_id, live, reason="role changed"
            )
        self._audit.record(
            AuditAction.USER_UPDATED,
            session=live,
            category=AuditCategory.ADMINISTRATION,
            target_type="user",
            target_id=user_id,
            detail=(
                f"Updated '{target.username}': role={role.name}, "
                f"active={is_active}."
            ),
        )
        if not is_active:
            self._authentication.terminate_user_sessions(
                user_id, live, reason="account deactivated"
            )

    def set_active(self, session: Session, user_id: int, active: bool) -> None:
        """Activate or deactivate an account."""
        live = self._access.require(session, Permission.USER_MANAGE, target=str(user_id))
        target = self._users.get_by_id(user_id)
        if target is None:
            raise ValidationFailedError(
                "User not found.", user_message="That account no longer exists."
            )
        if not active:
            if live.user_id == user_id:
                raise ValidationFailedError(
                    "Self-deactivation refused.",
                    user_message="You cannot deactivate your own account.",
                )
            self._guard_last_admin(target, new_role=target.role_name, new_active=False)

        self._users.set_active(user_id, active)
        self._audit.record(
            AuditAction.USER_ACTIVATED if active else AuditAction.USER_DEACTIVATED,
            session=live,
            category=AuditCategory.ADMINISTRATION,
            target_type="user",
            target_id=user_id,
            detail=f"Account '{target.username}' {'activated' if active else 'deactivated'}.",
        )
        if not active:
            self._authentication.terminate_user_sessions(
                user_id, live, reason="account deactivated"
            )

    def unlock(self, session: Session, user_id: int) -> None:
        """Clear an automatic lockout."""
        live = self._access.require(session, Permission.USER_MANAGE, target=str(user_id))
        self._users.set_locked(user_id, False, None)
        self._audit.record(
            AuditAction.USER_UNLOCKED,
            session=live,
            category=AuditCategory.ADMINISTRATION,
            target_type="user",
            target_id=user_id,
            detail="Account lockout cleared by an administrator.",
        )

    def reset_password(
        self, session: Session, user_id: int, new_password: str = ""
    ) -> str:
        """Reset an account's password.

        Args:
            new_password: an explicit password, or empty to generate one.

        Returns:
            The password to hand to the user. It is returned once, shown once,
            and never stored in plaintext or written to the audit trail.
        """
        live = self._access.require(session, Permission.USER_MANAGE, target=str(user_id))
        target = self._users.get_by_id(user_id)
        if target is None:
            raise ValidationFailedError(
                "User not found.", user_message="That account no longer exists."
            )

        password = new_password or generate_temporary_password()
        try:
            validate_password(
                password, min_length=self._authentication.policy.password_min_length
            )
        except ValidationError as exc:
            raise ValidationFailedError(str(exc), user_message=str(exc)) from exc

        hashed = self._passwords.hash(password)
        self._users.set_password(user_id, hashed.hash, hashed.algorithm, must_change=True)
        self._audit.record(
            AuditAction.PASSWORD_RESET,
            session=live,
            category=AuditCategory.ADMINISTRATION,
            target_type="user",
            target_id=user_id,
            detail=(
                f"Password reset for '{target.username}'. The account must "
                "change it at next sign-in."
            ),
        )
        self._authentication.terminate_user_sessions(
            user_id, live, reason="password reset"
        )
        return password

    def force_logout(self, session: Session, user_id: int) -> int:
        """Terminate every session of one account (§70)."""
        live = self._access.require(session, Permission.USER_MANAGE, target=str(user_id))
        return self._authentication.terminate_user_sessions(
            user_id, live, reason="administrative force-logout"
        )

    # ------------------------------------------------------------------
    # Safeguards
    # ------------------------------------------------------------------
    def _guard_last_admin(
        self, target: User, *, new_role: str, new_active: bool
    ) -> None:
        """Refuse a change that would leave no active administrator.

        Raises:
            ValidationFailedError: when the change would lock everyone out.
        """
        if not target.is_admin:
            return
        losing_admin = new_role.upper() != "ADMIN" or not new_active
        if not losing_admin:
            return
        if self._users.count_admins(active_only=True) <= 1:
            raise ValidationFailedError(
                "Refused: this is the last active administrator.",
                user_message=(
                    "This is the last active administrator account. Create or "
                    "activate another administrator before changing this one."
                ),
            )

    def statistics(self, session: Session) -> dict[str, Any]:
        """Account counts for the user management screen."""
        self._access.require(session, Permission.USER_MANAGE)
        return {
            "total": self._users.count_users(),
            "active": self._users.count_users(active_only=True),
            "administrators": self._users.count_admins(active_only=True),
            "active_sessions": len(self._users.list_sessions(active_only=True)),
        }
